# dockinout

Passing input/output into containers

dockinout utility allows to run commands like sftp-server or server-side rsync efficiently from a docker container.

The Docker client, when using `docker run -i image command`, does not connect stdin/stdout/stderr of the command to the original descriptors of the docker client invocation. Rather the client copies the data from those descriptors to the Docker server over HTTP-like protocol which in turn copies the data to/from the command running in the container.

This design allows for `docker run` to connect to a Docker server on a remote machine or in a VM. But for a Docker server that runs commands locally this adds an extra overhead of coping and parsing the data twice before they reach the command. When the input/output size is just few kilobytes the overhead does not matter as the time to create and start the container vastly exceeds the time for extra copies. But with bigger transfers this adds extra visible latency and CPU load. Another problem is that the file descriptor options that are set on the original input/output are not visible for the command in the container potentially leading to inefficiencies or misbehavior in corner cases.

The dockinout utility remedies this by passing the original file descriptor into the container over a UNIX socket and running the command in the container with those as stdin/stdout/stderr. After the initial setup the extra processes that utility creates exit. This leaves only the docker client process and the command inside the container running as will be the case with the original `docker run -i` invocation.
