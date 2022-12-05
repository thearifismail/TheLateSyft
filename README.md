# Host Inventory Grype
Host inventory Syft/Grype (HISG) is built using TheLateSyft from Dr. Brantly, Casey Williams, and Kent Aycoth.  For Getting JIRA cards, it uses Jira Nanny from Ashley Young

HISG does not use workstreams from TheLateSyft.  It, insteads, looks at the cluster a user is connected to, query for  projects/namespaces the user(account) has access to, and then at the deployments and images.  It then syfts and grypes the images found.  As of now, the vulnerability data is divided into four files based on fixed states, which are "fixed", "not-fixed", "wont-fix", and "unknown"

## Next To Do based on decisions made by the group.
Use data from Grype to update JIRA cards.
How to Fix images?
Adding this to PR Checks?

Unknown coming from nvd.nist.gov.  Question: When will they move out of unknown states or what do we do with it
Jira cards: split vuln in image or code base (front end)


# The Late Syft (Hackathon by Brantely, Casey, and Kent)
The Late Syft is a new open-source service that transitions existing SBoM(Software Build of Materials) functionality into a new "security as a service" open-source service. This will enable teams to see each individual build layer which will give the most accurate view of a container and its components. This ensures updated, automated and fresh copies on a regular basis and produces a more granular list of components/packages that are currently being monitored.

## Dependencies
- Syft - https://github.com/anchore/syft
- Grype - https://github.com/anchore/grype

The Late Syft utilizes several tools which consist of Syft and Grype to help analyze images and their layers for vulnerabilities.

## Getting started
The Late Syft project is favored to run in a Jenkins job environment such that you can automate results on an interval, git hooks, and send results to interested parties regularly. However, The Late Syft can be ran standalone by twiddling the bits by invoking the main `twiddle-the-bits.py` Python script.

You will need to install the Syft and Grype packages mentioned above as dependencies

## Adding your own Workstreams
You can add your own workstream into the "workstreams" folder. This consists of a JSON file containing your deployments name and the respective URL for that deployment.

## Usage
Run `pipenv shell` to create a shell for this project then run `pipenv install` to install project dependencies.

After you have setup the Python environment by following the above steps you will need to obtain an OSD API KEY (bearer token) from
the Production OSD Environment.

Then you can run the following command to twiddle the bits:
NOTE: 
`OSD_API_KEY` is obtained from the oc login bearer key token for your OSD instance.
The workstream you use to twiddle the bits is a file that lives in the Workstreams folder.
```
OSD_API_KEY="sha256~<your-key>" python twiddle-the-bits.py <enter-your-workstream-here>
```

You can also optionally create your own Jenkins job that invokes the `jenkins-job.sh` script. This can be easily imported by using
the jenkins-job-export.xml

## Contributing
MRs welcome

## Authors and acknowledgment
Dr. Brantley (dr.brantley@redhat.com), Casey Williams (caswilli@redhat.com, Kent Aycoth (kaycoth@redhat.com)

