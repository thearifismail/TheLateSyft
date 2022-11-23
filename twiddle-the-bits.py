import asyncio
import aiohttp
import json
import os
import logging
import subprocess
import config
import re

import openshift as oc

from cve_sifter import CVESifter
from kubernetes import client as kubeClient
from kubernetes import config as kubeConfig


def make_results_dir():
    if not os.path.isdir(config.SYFT_RESULTS_DIR):
        logging.info(f'Creating the "{config.SYFT_RESULTS_DIR}" directory')
        os.makedirs(config.SYFT_RESULTS_DIR)


def workstream_json_check():
    """
    Checks and validates the existence of the workstream json name supplied via command line argument.
    """
    if os.environ['WORKSTREAM']:
        if os.path.exists(f"{config.WORKSTREAMS_DIR}/{os.environ['WORKSTREAM']}.json"):
            logging.info("Workstream JSON Found!")
        else:
            logging.error("Unable to find Workstream JSON.")
            quit()
    else:
        logging.error('Job Failed to start. You must supply a supported "WORKSTEAM" as command line argument.')
        quit()


def define_component_list():
    """
    Opens and reads the OSD urls for each component with the supplied workstream JSON.
    """
    json_path = os.path.join(os.getcwd(), f"{config.WORKSTREAMS_DIR}/{os.environ['WORKSTREAM']}.json")
    with open(json_path, "r") as json_file:
        return json.loads(json_file.read())


async def production_image_lookup(worksteam_json_data):
    """
    Pulls deployment data from OSD for each component based on the supplied workstream JSON.
    """
    osd_results = []
    urls = []
    for component in worksteam_json_data["components"]:
        urls.extend(url for url in component.values() if url != "")
    async with aiohttp.ClientSession(headers={"Authorization": f"Bearer {config.OSD_API_KEY}"}) as session:
        tasks = get_tasks(session, urls)
        responses = await asyncio.gather(*tasks)
        for response in responses:
            osd_results.append(await response.json())
    return osd_results


def get_tasks(session, urls):
    """
    Sets up Async task for production_image_lookup.
    """
    return [session.get(url, ssl=True) for url in urls]


def osd_data_parser(osd_results):
    """
    Parses through returns OSD data and builds a dictionary of Pod Names and Quay Image Tag to be used by Syft.
    """
    deployment_data = {}
    for components in osd_results:
        if components["kind"] in ["Deployment", "DeploymentConfig"]:
            for component in components["spec"]["template"]["spec"]["containers"]:
                deployment_data[component["name"]] = component["image"]
        elif components["kind"] == "CronJob":
            deployment_data[components["metadata"]["name"]] = components["spec"]["jobTemplate"]["spec"]["template"]["spec"][
                "containers"
            ][0]["image"]
        elif components["kind"] == "Status" and components["reason"] in ["NotFound", "Forbidden"]:
            logging.error(
                f'The request for the deployment {components["details"]["name"].upper()} was "{components["reason"]}" in OSD. '
                "Please check the associated workstream template and verify all OSD URLs are correct."
            )
    
    for dep in deployment_data:
        print(f"Image in deployment: {dep}")
    # remove duplicate images
    logging.info(f"Number of images found: {len(deployment_data)}")
    unique_images = [*set(deployment_data)]

    for img in unique_images:
        print(f"image: {img}")
    logging.info(f"Number of unique images: {len(unique_images)}")

    return deployment_data


def clean_json(json_like):
    """
    Removes trailing commas from *json_like* and returns the result.  Example::
        >>> remove_trailing_commas('{"foo":"bar","baz":["blah",],}')
        '{"foo":"bar","baz":["blah"]}'
    https://gist.github.com/liftoff/ee7b81659673eca23cd9fc0d8b8e68b7
    """
    trailing_object_commas_re = re.compile(r'(,)\s*}(?=([^"\\]*(\\.|"([^"\\]*\\.)*[^"\\]*"))*[^"]*$)')
    trailing_array_commas_re = re.compile(r'(,)\s*\](?=([^"\\]*(\\.|"([^"\\]*\\.)*[^"\\]*"))*[^"]*$)')
    # Fix objects {} first
    objects_fixed = trailing_object_commas_re.sub("}", json_like)
    # Now fix arrays/lists [] and return the result
    return trailing_array_commas_re.sub("]", objects_fixed)


def syft_automation(deployment_data, csv_file_name, json_file_name):
    """
    Uses the deployment data collected from OSD and uses Syft to scan the identified images.
    Additionally, if any deployment uses a previously scanned image, it will use the cached
    results instead of rescanning.
    """
    syft_output_cache = {}
    with open(csv_file_name, "w") as file:
        file.write('"DEPLOYMENT NAME","QUAY TAG","PACKAGE NAME","VERSION INSTALLED","DEPENDENCY TYPE"')
    for deployment in deployment_data:
        deployment_name = deployment
        # quay_url = deployment_data.get(deployment)
        quay_url = deployment
        if quay_url in syft_output_cache:
            logging.info(f"{deployment.upper()} uses a previously scanned image '{quay_url}', using cached results.")
            with open(csv_file_name, "ab") as file:
                file.write(syft_output_cache[quay_url]["csv"])
            add_osd_metadata(deployment_name, quay_url, csv_file_name)
            with open(json_file_name, "ab") as file:
                file.write(syft_output_cache[quay_url]["json"])
        else:
            logging.info(f"Syfting through [{deployment.upper()} - {quay_url}]")
            command = f"syft {quay_url} --scope all-layers -o template -t {config.TEMPLATES_DIR}/syft_csv_and_json.tmpl"
            process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
            output, _ = process.communicate()
            csv_output = output.split(b"===SYFT_TEMPLATE_SEPARATOR===")[0]
            json_output = output.split(b"===SYFT_TEMPLATE_SEPARATOR===")[1]
            syft_output_cache[quay_url] = {"csv": csv_output, "json": json_output}
            with open(csv_file_name, "ab") as file:
                file.write(csv_output)
            add_osd_metadata(deployment_name, quay_url, csv_file_name)
            with open(json_file_name, "ab") as file:
                file.write(json_output)
        add_osd_metadata(deployment_name, quay_url, json_file_name)


def grype_automation(deployment_data, csv_file_name, json_file_name):
    """
    Uses the deployment data collected from OSD and uses Grype to scan the identified images.
    Additionally, if any deployment uses a previously scanned image, it will use the cached
    results instead of rescanning.
    """
    grype_output_cache = {}
    with open(csv_file_name, "w") as file:
        file.write(
            '"DEPLOYMENT NAME","QUAY TAG","VULNERABILITY ID","DATA SOURCE","VULNERABILITY SEVERITY","PACKAGE NAME","VERSION INSTALLED","FIXED VERSIONS","FIXED STATE""'
        )
    for deployment in deployment_data:
        deployment_name = deployment
        quay_url = deployment
        if quay_url in grype_output_cache:
            logging.info(f"{deployment.upper()} uses a previously scanned image '{quay_url}', using cached results.")
            with open(csv_file_name, "ab") as file:
                file.write(grype_output_cache[quay_url]["csv"])
            add_osd_metadata(deployment_name, quay_url, csv_file_name)
            with open(json_file_name, "ab") as file:
                file.write(grype_output_cache[quay_url]["json"])
        else:
            logging.info(f"Looking at [{deployment.upper()} - {quay_url}] for vulnerabilities to grype about.")
            command = f"grype {quay_url} --scope all-layers -o template -t {config.TEMPLATES_DIR}/grype_csv_and_json.tmpl"
            process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
            output, _ = process.communicate()
            csv_output = output.split(b"===GRYPE_TEMPLATE_SEPARATOR===")[0]
            json_output = output.split(b"===GRYPE_TEMPLATE_SEPARATOR===")[1]
            grype_output_cache[quay_url] = {"csv": csv_output, "json": json_output}
            with open(csv_file_name, "ab") as file:
                file.write(csv_output)
            add_osd_metadata(deployment_name, quay_url, csv_file_name)
            with open(json_file_name, "ab") as file:
                file.write(json_output)
            add_osd_metadata(deployment_name, quay_url, json_file_name)
        image_cleanup(quay_url)


def add_osd_metadata(deployment_name, quay_url, file_name):
    """
    Looks at the provided output and replaces the "PLACEHOLDER" text with the associated
    OSD metadata.
    """
    with open(file_name, "r") as file:
        filedata = file.read()
    filedata = filedata.replace("DEPLOYMENT_NAME_PLACEHOLDER", deployment_name)
    filedata = filedata.replace("QUAY_TAG_PLACEHOLDER", quay_url)
    with open(file_name, "w") as file:
        file.write(filedata)

def remove_blank_lines(file_name):
    """
    Looks at the provided output and removes blank lines introduced via Syft Output.
    """
    with open(file_name, "r") as file:
        filedata = file.readlines()
    with open(file_name, "w") as file:
        for line in filedata:
            if line != "\n":
                file.write(line)


def format_json(json_file_name):
    """
    Formats the JSON output file to make it valid JSON
    """
    with open(json_file_name, "r") as file:
        filedata = file.read()
        clean_filedata = clean_json(f"[\n{filedata}]")
    with open(json_file_name, "w") as file:
        file.write(clean_filedata)


def create_clean_result_files(csv_file_name, json_file_name):
    with open(csv_file_name, "w") as file:
        file.write("")
        logging.info(f"Generating clean {csv_file_name}")
    with open(json_file_name, "w") as file:
        file.write("")
        logging.info(f"Generating clean {json_file_name}")


def image_cleanup(quay_url):
    command = f"{config.CONTAINER_ENGINE} image rm -f {quay_url}"
    process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
    output, _ = process.communicate()
    if output != b"":
        logging.info(f'Clean Up: Removing "{quay_url}"')


def get_namespaces():
    """
    Checks cluster connection and resources avaialability.
    """
    try:
        projects = oc.selector("projects")
        oc_projects = [project.name() for project in projects]
        logging.info(f"Found {len(oc_projects)} projects/namespaces")
        for p in oc_projects:
            logging.info(f"Project: {p}")

        return oc_projects
    except Exception as e:
        logging.error("Job Failed to start. Can not connect to Kubernetes cluster resources.")
        logging.error(f"Problem: {e.msg}")
        quit()


# TODO: See if "oc" can be used to get deployments using a project name
def get_images(namespaces):
    # TODO: See if "oc" can be used to get deployments using a project name
    # Configs can be set in Configuration class directly or using helper utility
    kubeConfig.load_kube_config()
    api = kubeClient.AppsV1Api()

    images = []

    for ns in namespaces:
        deployments = api.list_namespaced_deployment(ns)
        for d in deployments.items:
            containers = d.spec.template.spec.containers
            for c in containers:
                images.append(c.image)

    logging.info(f"Total number images found: {len(images)}")

    # remove duplicate
    unique_images = [*set(images)]
    logging.info(f"Number unique images found: {len(unique_images)}")
    for im in images:
        logging.info(im)

    return unique_images


async def main():
    logging.basicConfig(
        format="%(asctime)s - %(levelname)s - %(message)s", datefmt="%d-%b-%y %H:%M:%S", level=logging.INFO
    )

    # TODO: Do we have to use workstreams?  Try getting access to all essentials and advisor services.
    workstream_json_check()
    make_results_dir()
    csv_file_name = f"{config.SYFT_RESULTS_DIR}/{config.WORKSTREAMS_DIR}-sbom.csv"
    json_file_name = f"{config.SYFT_RESULTS_DIR}/{config.WORKSTREAMS_DIR}-sbom.json"
    create_clean_result_files(csv_file_name, json_file_name)

    namespaces = get_namespaces()
    images = get_images(namespaces)
    # images = ["quay.io/cloudservices/insights-inventory:60f08b7"]
    os.system("./art/syft.sh")
    syft_automation(images, csv_file_name, json_file_name)
    remove_blank_lines(csv_file_name)
    remove_blank_lines(json_file_name)
    format_json(json_file_name)
    csv_file_name = f"{config.SYFT_RESULTS_DIR}/{os.environ['WORKSTREAM']}-vuln-scan.csv"
    json_file_name = f"{config.SYFT_RESULTS_DIR}/{os.environ['WORKSTREAM']}-vuln-scan.json"
    create_clean_result_files(csv_file_name, json_file_name)
    os.system("./art/grype.sh")
    grype_automation(images, csv_file_name, json_file_name)
    remove_blank_lines(csv_file_name)
    remove_blank_lines(json_file_name)
    format_json(json_file_name)

    sifter = CVESifter(json_file_name)

    fixed, not_fixed, wont_fix, unknown = sifter.sift_cves()

    logging.info(f"Fixed: {len(fixed)}")
    logging.info(f"Not-fixed: {len(not_fixed)}")
    logging.info(f"Wont-fix: {len(wont_fix)}")
    logging.info(f"Unkown: {len(unknown)}")
    


if __name__ == "__main__":
    asyncio.run(main())
