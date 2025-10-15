# jira-case-sync
Containerized version of the Sync service between Stellar Cases and Jira tickets (issues/requests)

There are 2 important files associated with the Sync service that are contained in this repository:
- config.yaml:
  * affects the behavior of the sync service (items to be sync'd between stellar and jira)
- jira-sync.env:
  * credentials (users / api keys) need to query the Stellar Cyber instance and the Jira projects

## Directions:

1. Clone this project on a target machine running docker
   
    `git clone https://github.com/stellarcyber/jira-case-sync.git`

2. Navigate to the cloned repo and build the docker image
   
    `docker build -t jira-case-sync .`

3. Create a directory on the docker machine that will contain the config. This diredtory will be bind mounted to the container at runtime.

   `mkdir /some/config/directory`

4. Copy the config template to the config directory named above and edit. All directives within the config file are commented as to behavior and expected values.

   `cp config-template.yaml /some/config/directory/config.yaml`
   
   `vi /some/config/directory/config.yaml`

5. Create a highly protected directory to store the environmental variables that contain all the credentials needed for the service.

   `mkdir /some/protected/directory`

6. Copy the env template to the protected directory and edit.

   `cp jira-sync-template.env /some/protected/directory/jira-sync.env`
   
   `vi /some/protected/directory/jira-sync.env`

7. Run the docker image using a bind mount to point to the config directory.
   - Replace **/some/config/directory** with the local directory used in step 3/4.
   - Replace **/some/protected/directory** with the local directory used in step 5/6.

   ``docker run --restart unless-stopped -d --mount type=bind,source=/some/config/directory,target=/app/data --env-file /some/protected/directory/jira-sync.env jira-case-sync:latest``

   Logs are stored in a `run.log` file within the config directory

   
 

    
