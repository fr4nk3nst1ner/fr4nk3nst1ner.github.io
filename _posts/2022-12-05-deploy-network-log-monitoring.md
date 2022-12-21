---
title: Deploy Network Log Monitoring
date: 2022-12-13 06:00:00 -500
categories:  [guides, monitoring, siem]
tags: [siem,monitoring,graylog,pi-hole,docker]
---

## Introduction 👋 

After spending the majority of my career in Offensive Security, I've always been curious of "what's on the other side." Naturally, an OffSec engineer must have _some_ awareness of blue team controls, such as EDR, to circumvent and avoid detections. 
 
An almost equal amount of my career has been in a consulting capacity, seeing dozens of different organizations' networks per year, each with various security maturity  implementations. Key takeaway over the years: it can actually be quite difficult to get caught. 

That is obnoxious and a hyper generalization I know, and thankfully not always true! But sometimes, many times, it is... Scary. 

Due to a lack of maturity in the area, a wonder of what TTPs can be detected by simple baselines through a combination of both endpoint and network monitoring, and an insatiable curiosity, I have put together this document.  

##### The Problem Statement 🧮 
I would like to lay the groundwork for building out a logging and monitoring capability in your lab that _could_ be scaled to support a small business. 

Detections have been inadequate in my experience. This is due to:
- Insufficient information security budgets
- Insufficient tests of controls in place 
- Inadequate visibility 
- Insufficient vendor coverage 
- Lack of technical capability and awareness the problem exists (for the latter, see bullet 2)

##### Re-invention of the Wheel 🛞 
I am not trying to rewrite materials that already exist. The Graylog team has some excellent documention, specifically for the [deploying in Docker](https://go2docs.graylog.org/5-0/downloading_and_installing_graylog/docker_installation.htm) portion of this writeup. Lots of what I'll be mentioning is redundant to these materials. Consider this a mapping of my thoughts of what would help / what I struggled with when setting up while going through the docs, a sidecar if you will. Please do consider taking a deep dive plunge in to these docs if you're wanting to go deep with Graylog. 

Also, this will be laying the groundwork for some future information I'll be releasing. I wanted to start with network monitoring, shift to endpoint monitoring, then cap it all off with threat intelligence. 

##### Selfish Bonus 💁🏼‍♂️
- I learn hosting a static blog and pipelining for updates 
- Writing blog and hosted content via Markdown (all this was written from an Obsidian note)


## A Note About Security Best Practices 🎶 

The purpose of this blog series is to share the implementation steps towards achieving a goal vs the details of either host hardening or triaging. An entire separate blog series could be written on hardening the same architecture we're creating. 

I'd advise that you take precautions when deploying this infrastructure in your lab as many of these techniques can increase the attack surface of your infrastructure. Goal here is to increase our observability in to our environment to increase our security posture vs lower. :) 

That said, I have included a Security Considerations section under each step. Do not consider this an exhaustive list of considerations rather areas my spidey sense would tingle with if I were to uncover on an engagement.

In short, items mentioned in this article  ARE NOT DESIGNED FOR USE IN PRODUCTION ENVIRONMENTS AND REQUIRE MORE SECURITY CONSIDERATIONS PRIOR TO SETUP AND DEPLOYMENT.  

## Definitions 🤓

[**Syslog**](https://www.rfc-editor.org/rfc/rfc5424): funtionality on various operating systems and appliances that enable the sending of system and kernel logging to a remote endpoint. Syslog as a logging vehicle will be a focus in this article.

[**ELK**](https://www.elastic.co/what-is/elk-stack): Elasticsearch + Logstash + Kibana = ELK. This powerful platform trio offered by the company Elastic enables lots of flexibility in both monitoring of endpoints as well as analyzing network traffic. 

[**Graylog**](https://www.graylog.org/): Log aggregation platform that functions similar to ELK. Leverages Elasticsearch as its database and MongoDB as its indexes. Not quite as expansive as ELK, particularly on endpoint monitoring, but extremely intuitive on network traffic log aggregation.

[**Docker**](https://docs.docker.com/) / [**Docker-Compose**](https://docs.docker.com/compose/) / [**Docker Swarm**](https://docs.docker.com/engine/swarm/): Containerization and container stack orchestration platforms respectively. This will be the tech discussed for spinning up infrastructure. I encourage you to [read the docs](https://docs.docker.com/) to learn more if you're currently uneducated or in need of refresher on this tech. 

#### Minimal Requirements
- Host, preferably Linux, with 16Gb RAM, 500Gb storage, multi-core processor 
- Docker
- Docker-compose
- "a" host or appliance that supports Syslog (e.g., Raspberry Pi, Ubuntu, Debian, MacOS, Windows)


## Step 1: Establishing our Docker Secrets 

In the spirit of practicing what we preach, we want to ensure secrets used in our containers are neither stored nor transmitted in plaintext. This would ensure that we are a buzz kill 🚭 to a malicious actor with low priv access to your system rather than a facilitator to their party. 🎉 
If the malicious actor has privileged access, well..your secrets will be compromised _and_ you probably have bigger fish to fry in terms of things you should be concerned with. 

The following will:
- Echo in your shell the password, sending to docker secrets where it will be stored encrypted, decrypted later during runtime 
- Creates a SHA-256 hash for the root Graylog account

```bash
docker swarm init
echo thisismyelasticpw | docker secret create ELASTIC_PASSWORD -
echo thisismygraylogpw | docker secret create GRAYLOG_PASSWORD_SECRET - 
echo -n thisismyrootpw | sha256sum | awk '{ print $1 }' | docker secret create GRAYLOG_ROOT_PASSWORD_SHA2 -  
docker secret ls
```

##### Business Considerations 🤝 

While the solution above leverages Docker Secrets, have in mind Docker Secrets has integrations with Hashicorp products (i.e., Vault, Nomad) for orchestrating and managing secrets (revoking, rotating, etc). 

As this solution grows and/or you're a home lab try hard like me, scalability and automation is up there with security (and godliness 😜). 

##### Security Considerations 🤔 

- Secrets management is a major problem in the security industry and has led to many breaches 
- Don't be a statistic, follow best practices here if you can and don't store or transmit secrets in plaintext 
- Disable your bash history, enter a space ahead of any command you're echo-ing from within your terminal, or remove your password from being stored in ~/.bash_history - or use stdin (e.g., `echo -n "Enter Password: " && head -1 </dev/stdin | tr -d '\n' | sha256sum | cut -d" " -f1` )
- Alternative to Docker secrets is to use environment variables - while less risky than hardcoded secrets, it's still stored within your session environment in plaintext (basically: .env is ok in lab or testing environments but not so much prod or for the biz)
- Read on "build time" vs "run time" secrets - although we aren't building images in this post, it's still an important concept to understand in terms of Docker security 


## Step 2: Reviewing and Deploying our Docker-Compose Stack

Below is a sample docker-compose.yml that incorporates a component stack we need to minimally get our setup working. 

A few notes worth mentioning:
- We are using a different version of Elasticsearch than what's shipped / recommended with graylog so that Kibana can read 
- This Elasticsearch version is the latest that is supported by Graylog and not the latest 
- Take caution when selecting Elasticsearch versions and changing after the fact - you can potentially lose data/indexes and might have to perform other actions when either upgrading or downgrading your versions 
- We have the xpack module enabled, foreshadowing what we'll be covering in a subsequent blog for endpoint monitoring 
- Where is Logstash? Thought you'd never ask! The "L" in ELK is missing because Graylog indexes using MongoDB and Kibana directly interacts with the Elasticsearch API 
- The account we're using (PGID and PUID 1100) is a non-privileged account 

```yaml
version: '3.7'
services:
    # MongoDB: https://hub.docker.com/_/mongo/
    mongo:
      image: mongo:4.2
      container_name: mongodb-graylog
      restart: unless-stopped
      hostname: mongodb-graylog
      environment:
        - PUID=1100
        - PGID=1100
      volumes:
        - mongo_data:/path/to/graylog/mongo
        - /path/to/graylog/mongo:/data/db
    elasticsearch:
      container_name: elastic-graylog
      restart: unless-stopped
      hostname: elastic-graylog
      ports:
      - 9200:9200
      - 9300:9300
      image: docker.elastic.co/elasticsearch/elasticsearch:7.17.0
      volumes:
      - es_data:/path/to/graylog/elasticsearch
      - /path/to/graylog/elasticsearch:/usr/share/elasticsearch/data
      secrets:
        - ELASTIC_PASSWORD
      environment:
        - discovery.type=single-node
        - http.host=0.0.0.0
        - http.port=9200
        - ELASTIC_USER=elastic
        - ELASTIC_PASSWORD=/run/secret/ELASTIC_PASSWORD
        - http.cors.enabled=true
        - http.cors.allow-headers=X-Requested-With,X-Auth-Token,Content-Type,Content-Length,Authorization
        - http.cors.allow-credentials=true
        - network.host=0.0.0.0
        - "ES_JAVA_OPTS=-Dlog4j2.formatMsgNoLookups=true -Xms4g -Xmx4g"
        - ES_HEAP_SIZE=2g
        - PGID=1100
        - PUID=1100
        - ilm_enabled=false
        - xpack.security.enabled=true
        - xpack.security.authc.api_key.enabled=true
      ulimits:
        memlock:
          soft: -1
          hard: -1
      deploy:
        resources:
          limits:
            memory: 8g
            cpus: '4.0'
          reservations:
            memory: 4g
            cpus: '2.0'

    graylog:
      container_name: graylog
      restart: unless-stopped
      hostname: graylog
      image: graylog/graylog:4.3.9
      secrets:
        - GRAYLOG_PASSWORD_SECRET
        - GRAYLOG_ROOT_PASSWORD_SHA2

      volumes:
        - graylog_data:/path/to/graylog/graylog
        - /path/to/graylog/graylog/journal:/usr/share/graylog/data/journal
        - /path/to/graylog/graylog/config:/usr/share/graylog/data/config
        - /path/to/graylog/graylog/node-id:/etc/graylog/server/node-id
      environment:
        - http_bind_address=0.0.0.0
        - PUID=1100
        - PGID=1100
        # CHANGE ME (must be at least 16 characters)!
        - GRAYLOG_PASSWORD_SECRET=/run/secret/GRAYLOG_PASSWORD_SECRET
        - GRAYLOG_ROOT_PASSWORD_SHA2=/run/secret/GRAYLOG_ROOT_PASSWORD_SHA2
        - GRAYLOG_HTTP_EXTERNAL_URI=http://localhost:9000/
        - TZ=America/Chicago
        - allow_leading_wildcard_searches=true
      entrypoint: /usr/bin/tini -- wait-for-it elasticsearch:9200 --  /docker-entrypoint.sh
      restart: always
      depends_on:
        - mongo
        - elasticsearch
      ports:
        # Graylog web interface and REST API
        - 9000:9000
        #syslog 514 tcp
        - 514:514
        #beats5044tcp
        - 5044:5044
        #beats5044udp
        - 5044:5044/udp
        #Syslog 514 udp
        - 514:514/udp
        # Syslog TCP
        - 1514:1514
        # Syslog UDP
        - 1514:1514/udp
        # GELF TCP
        - 12201:12201
        # GELF UDP
        - 12201:12201/udp


    kibana:
      hostname: kibana
      container_name: kibana
      restart: unless-stopped
      #network_mode: "host"
      image: docker.elastic.co/kibana/kibana:7.17.0
      ports:
        - "5601:5601"
      environment:
        - "XPACK_FLEET_AGENTS_FLEET_SERVER_HOSTS=[\"http://localhost:8220\"]"
        - "XPACK_FLEET_AGENTS_ELASTICSEARCH_HOSTS=[\"http://localhost:9200\"]"
        - PGID="1100"
        - PUID="1100"
        - TZ='America/Chicago'
      volumes:
        - '/path/to/graylog/kibana.yml:/usr/share/kibana/config/kibana.yml'
      cap_add:
        - NET_ADMIN
      restart: unless-stopped
      depends_on:
        - elasticsearch

volumes:
  mongo_data:
    driver: local
  es_data:
    driver: local
  graylog_data:
    driver: local

secrets:
  ELASTIC_PASSWORD:
    external: true
  GRAYLOG_PASSWORD_SECRET:
    external: true
  GRAYLOG_ROOT_PASSWORD_SHA2:
    external: TRUE
``` 

Next, let's deploy the stack:

```bash
docker stack deploy --compose-file /path/to/docker-compose.yml graylogstack
docker stack ps graylogstack
``` 


If all goes well, our system should be running. 

![Screenshot](/assets/Pasted image 20221209154942.png) 

Navigate to the IP of your host on port 9000, and voila - you should see the login page: 

![Screenshot](/assets/Pasted image 20221209163323.png)

##### Business Considerations 🤝 
- Thoroughly review the vendor EULAs to ensure your not violating any terms of service by using these products and versions 
- Understand that the handcuffed version of Elasticsearch that Graylog supports might lack feature that would interest you and therefore you may consider a second instance of ELK that runs the latest version (will cover this in more depth in the next blog)

##### Security Considerations 🤔 
- You'll want to monitor the Elasticsearch version listed above for vuln disclosures and possible patches so that you're aware of the risk you're taking on by not upgrading
- If the Elasticsearch version is not an acceptable risk, use the Graylog recommended version but understand xpack (endpoint monitoring) can't be used in the community version 
- Don't use a root or highly privileged account but rather an account provisioned with only the permissions required by the container or stack services 
- Repeat of we're not building images but rather pulling already existing images (Graylog, MongoDB, Elasticsearch); however, in a production environment, consider the use of [distro-less](https://github.com/GoogleContainerTools/distroless) or something like [Container-Optimized OS](https://cloud.google.com/container-optimized-os/docs/) vs CentOS, Debian, Alpine 


## Step 3: Setting up Graylog  

First, let's login to Graylog using the `GRAYLOG_ROOT_PASSWORD_SHA2` password we configured in Docker Secrets (username is `admin`). 

![Screenshot](/assets/Pasted image 20221209163416.png)

Graylog uses MongoDB to store its indexes which are fed by various inputs. Below we have configured a syslog input for UDP port 514 from `System --> Inputs --> Launch New Input --> Syslog UDP` keeping everything default except `Title`:

![Screenshot](/assets/Pasted image 20221209163953.png)

Next lets setup some indexes. We'll talk more about this in a second, but first lets knock out some basics: 

`System --> Indices --> Create Index Set`

Add a title, description, and index prefix which are all required fields: 

![Screenshot](/assets/Pasted image 20221209164511.png)

Indexes offer various settings that can fit your storage and retention strategy. Ensure that you take extra precaution here to: 
1. Not violate any laws or regulations with the types of data that you're storing
2. Are not attempting to store more data than you have storage space 

The method we have chosen for our indexing strategy is to store 50Gb per index and rotate a maximum of 5 times. This ensures this single index and associated rotations will store up to 250Gb (50Gb x 5 rotations).

![Screenshot](/assets/Pasted image 20221209164728.png)

For more information on log collection, I'd highly recommend reviewing Graylog's documentation: 

https://docs.graylog.org/docs/planning

##### Business Considerations 🤝 
- Retention strategy: ensure you have a very firm understanding as to _what_ you're logging and that whatever is being logged is in alignment and complies with policy, governance, laws, and regulations
- Storage strategy: these indexes can become enormous beyond magnitude of comprehension if you misconfigure. Ensure that your index sizes and rotation are in alignment with your storage capabilities 
- These indexes require swift I/O on your storage, refer to the Graylog documentation when and where to apply different storage media (SSD vs HDD)

##### Security Considerations 🤔 
- Today: Consider lowering your retention because: the longer passwords are insecurely stored, the higher the likelihood that the secret will be leaked 
- Future: Take mental note to remind yourself to check, double check, and triple check you don't have apps / hosts dumping secrets or other sensitive data (PII, PHI, etc) in your logs 



## Step 4: Configure Hosts to Send Logs to Graylog 

Various operating systems, network appliances,  embedded devices, and other types of devices have many different methods for configuring their syslog and/or netconsole configuration. For our example, we'll be using a Raspberry Pi. And not just any Raspberry Pi, a Raspberry Pi that's been loaded with [Pi-Hole](https://pi-hole.net/)! 

[SSH](https://www.raspberrypi.com/documentation/computers/remote-access.html) in to your Raspberry Pi hostand install rsyslog:

```bash
ssh pi@ipaddress
sudo apt-get update && sudo apt-get install rsyslog vim -y 
```

Once installed, run the following command to create and edit our syslog config file:

`sudo vim /etc/rsyslog.d/22-graylog.conf`

Paste in the following contents, ensuring you change the target to be the IP of your Graylog host:

```
# Forward all logs to graylog:
*.*	action(type="omfwd" target="graylogip" port="514" protocol="udp"
                      action.resumeRetryCount="100"
                      queue.type="linkedList" queue.size="10000")

# Define extra log sources:
module(load="imfile" PollingInterval="30")
input(type="imfile" File="/var/log/pihole.log"
         Tag="pihole"
         StateFile="/var/spool/rsyslog/piholestate1"
         Severity="notice"
         Facility="local0")
input(type="imfile" File="/var/log/pihole-FTL.log"
         Tag="piFTL"
         StateFile="/var/spool/rsyslog/piFTLstate1"
         Severity="notice"
         Facility="local0")
```

Restart the rsyslog service:

`sudo systemctl restart rsyslog`

Verify you now have traffic incoming to your Graylog Input that we setup earlier: 

`System --> Inputs --> Show Received Messages`

![Screenshot](/assets/Pasted image 20221209171424.png)


## Step 5: Configure Stream and Verify Data Fields 

Now that we have our input and index setup, let's create a stream. Click Streams in the upper right corner and you'll see that we have none - let's change that! Click create new stream and let's set one up. 

Name it whatever you want. Select your input and index you created from the earlier steps. Select the radio button to indicate you want it to remove the entry from the default stream. This prevents duplicate entries and keeps the default stream clean for future use. 

![Screenshot](/assets/Pasted image 20221209171702.png)

Click Manage Rules, Add stream rule, and select source contains pihole (substitute with whatever hostname your syslog host will have). Also, be sure to select the radio button `A message must match at least one of the following rules.

![Screenshot](/assets/Pasted image 20221209171923.png)

Save, click Start Stream, and go back to streams (Streams tab) and click your stream name you created. Voila, you should now have data coming through your stream. 

![Screenshot](/assets/Pasted image 20221209172204.png)

These are being indexed using the strategy you defined from earlier and the fields should be extracted via our input extractor or pipeline, depending which one you chose. But let's check! 

![Screenshot](/assets/Pasted image 20221209172401.png)

Boom. Messages are being written to the index and we're on index 0 of 4 (writes to 5 indexes before deleting). 




## Step 6: Extractors and Pipelines

Do yourself a favor: grab a coffee, this is the point you'll need it ... ☕️ 

Log management, aggregation, and correlation tends to circle around the idea of actually making sense of raw log data received. A heavy component of this is cross-platform normalization of data received. 

Maybe you have a Linux host that refers to its source IP as "src_ip" and a network appliance that refers to its source IP as "ipsrc". In order to make sense of this, you will need a common nomenclature to refer to data types. 

Additionally, syslog data consists of a text blob that contains a raw, unencoded message. Extracting data types in to fields to be stored within Elasticsearch is the second component. 

![Screenshot](/assets/Pasted image 20221209165350.png)

For ELK, this is where Logstash comes in for slicing and dicing your logs into something meaningful and useful. For Graylog, you have two options: extractors and pipelines. Since we're using Graylog, let's move forward. 

I'll provide an example of both an extractor as well as pipeline that can both accomplish the same thing. However, pipelines are more efficient and is recommended, particularly for high transaction processing. Heavy processing input extractors will lead to a backlog of unprocessed messages which will eventually lead fill buffers, ipso facto: downtime. 

Example Scenario: we're presented with the raw Syslog message below.  We want to extract the `blah.com` portion of the message and save it in its own field called `domain` for further processing later. (we'll get to this in a later blog post) 

```
pihole pihole Dec 9 18:00:07 dnsmasq[348]: query[A] blah.com from 1.1.1.1
```

##### Input Extractors Example Config Example

Go to: 
`System --> Inputs --> Manage Extractors --> Get Started --> Load Message`

Then:
`Get started --> Load Message --> Select extractor type --> Regular expression`

![Screenshot](/assets/Pasted image 20221209175321.png)

Enter in the following regex: `^.*query\[A\](.+?)\s.*`

I'd recommend setting a condition. Remember, input processing via extractors is a relatively very high burden for compute. The more you can carve down cycles used for processing, the better. Store the field as "domain", give it a title that will identify it, and, for normalization purposes, add a convertor to change the output to lowercase. Click "Try" to verify it worked with the message that loaded (top of the screen). 

![Screenshot](/assets/Pasted image 20221209181915.png)

_note_: This only works for messages containing "query\[A\]" as shown in the below example. You'll need to adjust this regex depending on your scenario and other DNS record types in this example. 

`pihole-mediaserver pihole Dec 9 18:00:07 dnsmasq[348]: query[A] daisy.ubuntu.com from 0.0.0.0`

##### Pipeline for Message Processing Example (recommended)

Another scenario: we have a raw Syslog message and are wanting to extract IP address of the host making the DNS request in to a field called `src_ip`: 

```
pihole pihole Dec 9 18:41:40 dnsmasq[348]: reply suspiciousdomain.com from 192.168.1.56
```

Navigate to the following: 

`System --> Pipeliness --> Manage Rules --> Create Rule`

Pase in the following Rule source: 

```
rule "parse ip from pihole domain fields"

when
  has_field("source") 
  AND  contains(to_string($message.message), "from" , true) 
  AND ! is_ip("0.0.0.0")

// example of how to create an array of items to process 
  AND ! 
  (
    contains(to_string($message.message), "127.0.0.1" , true) OR
    contains(to_string($message.message), "::" , true) 
  )
  
then
  let j = regex("from(.*)$", to_string($message.message));
  set_field("dns_source_ip", j["0"]);
  
end
```

In the example above, we're getting a little more complex with our rules. I wanted to provide an example demonstrating how you can create an array of items to either include or not include as part of processing. 

Click `Manage Pipelines` and `Add new pipeline`, naming it something useful to you. Click `Edit connections` and add your stream we created from before. Stage 0 in the pipeline will exist by default. Click `Edit` for Stage 0 and select `None or more rules on this stage match` radio button and add our stage rule we created from the previous step and save. Should look something like this at this point: 

![Screenshot](/assets/Pasted image 20221209183326.png)

Now let's test the pipeline rule. Go back to your streams and copy the body of a message so that we can test that the rule works. Remember, we're trying to trigger the rule here so make sure to capture a message that will trigger. In our case, we're trying to extract the domain from a message containing "reply" in the body. 

Or if you're lazy, just copy-pasta the following message for testing: 

```
pihole pihole Dec 9 18:41:40 dnsmasq[348]: reply suspiciousdomain.com from 192.168.1.56
```

Paste the contents of the message above (or your own) in the Simulator Raw Message window. Select your stream name from the drop down, and Raw String from the Message code drop down: 

`System --> Pipelines --> Simulator`

![Screenshot](/assets/Pasted image 20221209192122.png)

And she works! 

_Note_: my regex skills are hot garbage. For both input processing and pipelines, you'll want to streamline your rexex to ensure that its functioning most efficiently to avoid processing overhead. 

Click one of the logs and ideally you should see the `dns_source_ip` field containing the IP from the message from your stream. 





## What's Next? 

Now that we've gotten a start for some things you could do at home, the next piece I want to take it to the next level wtih more Pipelines and introduce Lookup Tables. 

Next, we'll dive in to ELK and Kibana so we can start looking at other things beyond the network, such as endpoints. 

To tie the bow on it all, I'll also introduce how Threat Detection can be used with all of this. There is a lot you can glean once you have the information parsed into a mechanism where you can start analyzing. However, getting it to that point is easier said than done. That's where these guides come in and can hopefully enable you to learn from my mistakes and lend a helping hand to getting something setup!

Goal is to hopefully get you to something like the following in the near future: 

![Screenshot](/assets/Pasted_Image_12_9_22__8_18_PM.jpg)






