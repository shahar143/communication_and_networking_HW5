
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#define PORT_PLUS_1  9999
#define PORT 9998
#define MAXLINE 1024
#define MAXLINE 1024


int total_recv = 0;
int total_send = 0;

int main(int count , char *argv[]) { // Here the argument to get the ip host from command line.



    int sockfd=-1,sockfdr=-1;
    char buffer[MAXLINE];
    char *hello = "Hello from client"; // the message to send to port PORT_PLUS_1
    struct sockaddr_in	 servaddr;

    if (count==1){
        printf("Usage: %s <hostIP>\n", argv[0]);
        exit(-1);
    } else if (count>2){
        printf("Too many arguments!\n");
    }
    else {
        char *args[1];


        args[0] = argv[1];
        ////////////////////////////////////////////////////////////////////////////////

        // Creating socket file descriptor  (for PORT_PLUS_1)
        if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            perror("socket creation failed");
            exit(EXIT_FAILURE);
        }else{
            printf("Create a sockfd\n");
        }
        memset(&servaddr, 0, sizeof(servaddr));

        // Filling server information
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(PORT_PLUS_1);
        servaddr.sin_addr.s_addr = inet_addr(args[0]);

        ////////////////////////////////////////////////////////////////////////////////



        ////////////////////////////////////////////////////////////////////////////////


        int len;
        struct sockaddr_in servaddr2;

            // Filling server information
            servaddr2.sin_family = AF_INET; // IPv4
            servaddr2.sin_addr.s_addr = INADDR_ANY;
            servaddr2.sin_port = htons(PORT);


            if ((sockfdr = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
                perror("socket creation failed");
                exit(EXIT_FAILURE);
            }else{
                printf("Success create a another socket\n");
            }


            // Bind the socket with the server address
            if ( bind(sockfdr, (const struct sockaddr *)&servaddr2,
                      sizeof(servaddr2)) < 0 )
            {
                perror("bind failed");
                exit(EXIT_FAILURE);
            }
            else{
                printf("Success Bind\n");
            }

            ////////////////////////////////////////////////////////////////////////////////





        len = sizeof(servaddr2); // the size of another socket (recvfrom).
        float randNumber = 0;

        while(1) {


           if(recvfrom(sockfdr, (char *) buffer, MAXLINE,
                         0, (struct sockaddr *) &servaddr2,
                         &len)<0){
                perror("recvfrom");

            }else{

               total_recv++;
            }
           




            randNumber = ((float) random()) / ((float) RAND_MAX); // getting a random number in each iteration.
            printf("%f\n",randNumber);

            if (randNumber > 0.5) { // if the random number is greater than 0.5 , then send the datagram
                                    // which we get from the sender, else nothing go back to recv another datagram.


                                    //Note here we send using serveraddr , to send to ip host from command line and port_plus.
                if (sendto(sockfd, (const char *) buffer, strlen(buffer),
                           MSG_CONFIRM, (const struct sockaddr *) &servaddr,
                           sizeof(servaddr))<0){
                    perror("send");
                } else{

                        total_send++;
                }



            }

            bzero(buffer, sizeof(buffer));

            sleep(1);

            // print the percent in each iteration of sends from all recvs...
            float percent = ((float )total_send/(float )total_recv)*100;
            printf("rcv = %d \t send =%d \t  percent_sends = %.2f \n",total_recv,total_send,percent);

        }


    }


    close(sockfdr);
    close(sockfd);
    return 0;
}


