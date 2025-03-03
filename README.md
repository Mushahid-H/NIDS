Change the emails and username and password with your own.

    docker build -t nid .
    docker run -d --privilleged --net=host nids
    docker exec -it conainer_id bash

To generate alert: 
    
    nmap -p 22,80 localhost_ip:port_Number

To run test:

        pip install pytest
        pytest test/
