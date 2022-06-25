/***********************************************************************************
 *
 * Author: mouhssine el idrissi, youssef el bab
 * Professor: Dr. Briffaut Jeremy, 
 * Creation Date: 02 Mars 2022
 * Due Date: 09 Juin 2022
 * Assignment: server client application
 * Filename: client.c
 * Purpose: allow a server to get scan all the information of client,get his adress IP,
 send file and excute them.
 * compile: make client
 * Run: ./client <@ip_server>
 *
 **********************************************************************************/ 
//client.c
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <linux/if.h>
#include <ifaddrs.h>
#define TRUE 1
#define FALSE 0
#define SIZE 1024
#define TAILLE 512
#define SA struct sockaddr
/*******************************************/

//initialisation des functions
void authentifier(int fd, char* check);
void envoyer(int connfd, char* buffer);
void recevoir(int connfd, char* buffer);
char * get_ipaddress();
void receivefile(char *filename);
void sauvegader_fichier(char *filename,char *buffer);
FILE* ouvrir_fichier(char* nom_fichier, char*option);
void verifie_checksum(char *resulat_recu, char * resulat_gener);
char* generer_sha1(char* fichier);
void execscript(char *filename);
void transfer(char *destination, char *source);
char * loadFile(char *name, char  *fileBuff);
/*******************************************/

//fonction receive file
void receivefile(char *filename){
    //declaration des variables
	
    int port = 7001;
    int listenfd;
     // La structure avec les informations du serveur
    struct sockaddr_in serv_addr = {0};
    int z;
    char erreur[SIZE]; 
    char sha1[SIZE];
    char contenu_file[SIZE];
    char sha2[SIZE];
    char sha3[SIZE];
    
    
    
    printf("[+] Création de la socket Serveur du port %d...\n",port);
    
    // Création de la socket serveur
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if(listenfd<0){
	    perror("[-] Erreur: la socket ne peut pas etre crée \n");
    }
    printf("[+] la socket a été bien crée \n");
    //applique l'option setoptsocket SO_LINGER
   struct linger so_linger;

    so_linger.l_onoff = TRUE;
    so_linger.l_linger = 0;
    z=setsockopt(listenfd,SOL_SOCKET,SO_LINGER,&so_linger,sizeof so_linger);
    if(z){
  	perror("setsocketopt(2)");
  	}
    
    
    //Initialisation de la structure sockaddr
    serv_addr.sin_family = AF_INET;
    //Accepte les connexions depuis n'importe quelle adresse
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    // Le port sur lequel la socket va écouter
    serv_addr.sin_port = htons(port);
    
    char erreur[SIZE]; 
    // Association de la socket avec la structure sockaddr
    if(bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr))<0){
		 sprintf(erreur,"[-] Erreur : Bind a été echoué pour le port %d\n", port);
         	 perror(erreur);
		}
    printf("[+] Bind du serveur a été bien créé %d\n",port);
    
    //La socket écoute pour des connexions
    if(listen(listenfd, 10)<0){
		sprintf(erreur,"[-] Erreur : listen a été echoué pour le port %d\n", port);
		perror(erreur);
         	}
    printf("[+] Le port %d est en train d'écouter ...\n", port);
    
    // Accepte la connexion d'une socket client
	printf("[+] Acceptation de la connexion au port %d\n",port);
        int connfd = accept(listenfd, (struct sockaddr*)NULL, NULL);
    // recevoir le rÃ©sultat de la fct d'hashage

    bzero(&sha1, SIZE);
    recevoir(connfd, sha1);
  //  usleep(100);
    // recevoir le contenu de ficher send.sh

     bzero(&contenu_file, SIZE);
     recevoir(connfd, contenu_file);
     
     //socker le contenu de ficher dans recv.sh
 
     sauvegader_fichier(filename, contenu_file);
     
     //appliquer la fonction d'hashage sur le fichier reçu 

     bzero(&sha2, SIZE);
     strcpy(sha2, generer_sha1(filename));
    
    // verifie_checksum de fichier récu et le sauvegarder
      verifie_checksum(sha1, sha2);
      
      //réinistialiser les buffers sha1 et sh2
      bzero(&sha2, SIZE);
      bzero(&contenu_file, SIZE);
      bzero(&sha2, SIZE);
      
     // exécuter le script
      execscript(filename);
    
     //transfer le contenu de ficher df.txt
     char *nom_fichier1 = "execution.sh";
     transfer(nom_fichier1, "/tmp/df.txt");
     
     // appliquer la fonction d'hashage sur le fichier execution 

     bzero(&sha3, SIZE);
     strcpy(sha3, generer_sha1(nom_fichier1));
     
     //envoyer le résultat de la fonction d'hachage du fichier avant de l'execution
     envoyer(connfd, sha3); 
     
     // envoyer le  fichier de l'exÃ©cution 
      strcpy(contenu_file, loadFile(nom_fichier1,contenu_file));

      envoyer(connfd, contenu_file);
      bzero(&contenu_file, SIZE);
      
    
    
    
     //fermé la connection sur le port 7001
   // shutdown(connfd, SHUT_RD);
    //    sleep(200); // wait little bit en (ms)
   // close(connfd);
   // close(listenfd);
}

//fonction load data from file
char * loadFile(char *name, char  *fileBuff){
	   FILE *pFile = NULL;
	 char c;
	 int i = 0;
	 pFile = fopen(name, "rt");
	 while((c =fgetc(pFile)) != EOF){
	 fileBuff[i] = c ;
	 i++;
	 
	 }
	  // terminate
	  fclose (pFile);
return fileBuff;
}

void transfer(char *destination, char *source){
	FILE* fp1 = ouvrir_fichier(source, "r+");
	FILE* fp2 = ouvrir_fichier(destination,"r+" );
	char chaine[SIZE];
	if(fp1!= NULL){
		while(fgets(chaine,sizeof(chaine), fp1) != NULL){
		fputs(chaine, fp2);
		}
	}
	
 	 fclose(fp1);
  	 fclose(fp2);

}

//fonction d'execution de script
void execscript(char *filename){  
	char buff[SIZE];
        printf("[+] le fichier est en train de l'execution...\n");
 	snprintf(buff, sizeof(buff), "sh %s",filename); 
 	system(buff);
	printf("\n end of execscript. \n");
}


//fonction generation de checksum
char* generer_sha1(char* fichier){
	char cmd[SIZE];
	char* token;
	char ligne[SIZE];
        char sha1_file[TAILLE];
	sprintf(sha1_file, "sha1_%s", fichier);
	sprintf(cmd, "sha1sum -t %s > %s", fichier, sha1_file);
	system(cmd);
	
	FILE* fp = ouvrir_fichier(sha1_file, "a+");
	fgets(ligne, SIZE, fp);
	fclose(fp);
	char *str1;
	str1 = strdup(ligne);
	token = strsep(&str1, " ");
	printf("[+] resultat de la fonction d'hachage SHA1 est: %s\n", token);
	return token;

}


//function verifie _checksum
void verifie_checksum(char *resulat_recu, char * resulat_gener){
	if(strcmp(resulat_recu, resulat_gener) == 0){
		printf("[+] le fichier n'est pas été modifié lors d'envoie \n");
	}
	else{	
		printf("[-] le fichier a été modifié lors d'envoie \n");
	}
	
}

//sauvegader dans le fichier
void sauvegader_fichier(char *filename, char *buffer){
  FILE *fp= ouvrir_fichier(filename, "r+");
  fprintf(fp, "%s", buffer);
  printf("[+] le fichier a été sauvegardé\n");
  fclose(fp);

}

//fonction ouvrir le fichier
FILE* ouvrir_fichier(char* nom_fichier, char*option){
	FILE* fp = fopen(nom_fichier, option);
	if(fp == NULL){
	        char erreur[SIZE];
		sprintf(erreur,"[-] Erreur : l'ouverture du fichier '%s' est echouée..\n",nom_fichier); 
		perror(erreur);	
		}
	return fp;
}
//fonction authentification
void authentifier(int fd, char* check){
	char pwd[SIZE];
	char etat_password[SIZE];
	if( strcmp(check,"valide") == 0){
		printf("entre mdp : ");
		scanf("%s", pwd);
	}
	else{
		printf("nouvelle inscription \n");
		printf("entre mdp : ");
		scanf("%s", pwd);
		}
	
	//send le mdp pour l'sauvegarder dans listClients //
	 send(fd, pwd, sizeof pwd,0);
	 printf("le passrowd est :%s \n", pwd);
	 bzero(&etat_password, SIZE);
	 recevoir(fd, etat_password);
	 //vérification de état, si mdp valide reste , sinon on quite la connection
	if(strcmp(etat_password, "Mot de passe valide\n") != 0){
		printf("\n #########  [+] Merci de reconnecter avec un mot de passe valide #########\n");
		close(fd); 
            exit(1);
		}
	else{
		printf("\n ******************	Bienvenue à vous M Client	****************** \n\n");
	}

	 
	 
	 
}

//fonction envoyer 
void envoyer(int connfd, char* buffer){
   if(send(connfd, buffer, strlen(buffer)+1, 0)< 0){
	        char erreur[SIZE];
		sprintf(erreur,"[-] Erreur : le message '%s' n'a pas été envoyé...\n",buffer); 
		perror(erreur);	
	   }
 else {
	   printf("[+] le message a été envoyé: %s\n", buffer);}
	   
}
//fonction recevoir
void recevoir(int connfd, char* buffer){
	if(recv(connfd, buffer, SIZE, 0) < 0)
        {
	   perror("[-] Erreur: le message n'a pas été recu \n");
           exit(errno);
        }
	else{
		printf("[+] le message a été recu : %s\n", buffer);
	}

}


//fonction d'inscription dans le serveur
void inscrire(int fd){
	char* ip = get_ipaddress();

	send(fd, ip, strlen(ip),0);	
	
}

//// fonction pour rÃ©cupÃ©rer l'@ip du client0000
char * get_ipaddress()
{
     //create an ifreq struct for passing data in and out of ioctl
        struct ifreq my_struct;
     	char * addr;
     	
        //declare and define the variable containing the name of the interface
        char *interface_name="ens33";   //a very frequent interface name is "ens33";
     
        //the ifreq structure should initially contains the name of the interface to be queried. Which should be copied into the ifr_name field.
        //Since this is a fixed length buffer, one should ensure that the name does not cause an overrun
        size_t interface_name_len=strlen(interface_name);
     
        if(interface_name_len<sizeof(my_struct.ifr_name))
        {
            memcpy(my_struct.ifr_name,interface_name,interface_name_len);
            my_struct.ifr_name[interface_name_len]=0;
        }
        else
        {
            perror("Copy name of interface to ifreq struct");
            printf("The name you provided for the interface is too long...\n");
        }
     
        //provide an open socket descriptor with the address family AF_INET
        /* ***************************************************************
         * All ioctl call needs a file descriptor to act on. In the case of SIOCGIFADDR this must refer to a socket file descriptor. This socket must be in the address family that you wish to obtain (AF_INET for IPv4)
         * ***************************************************************
         */
     
        int file_descriptor=socket(AF_INET, SOCK_DGRAM,0);
     
        if(file_descriptor==-1)
        {
            perror("Socket file descriptor");
            printf("The construction of the socket file descriptor was unsuccessful.\n");
            return 0;
        }
     
        //invoke ioctl() because the socket file descriptor exists and also the struct 'ifreq' exists
        int myioctl_call=ioctl(file_descriptor,SIOCGIFADDR,&my_struct);
     
        if (myioctl_call==-1)
        {
            perror("ioctl");
            printf("Ooops, error when invoking ioctl() system call.\n");
            close(file_descriptor);
            return 0;
        }
     
        close(file_descriptor);
     
        /* **********************************************************************
         * If this completes without error , then the hardware address of the interface should have been returned in the  'my_struct.ifr_addr' which is types as struct sockaddr_in.
         * ***********************************************************************/
     
      //extract the IP Address (IPv4) from the my_struct.ifr_addr which has the type 'ifreq'
     
        /* *** Cast the returned address to a struct 'sockaddr_in' *** */
        struct sockaddr_in * ipaddress= (struct sockaddr_in *)&my_struct.ifr_addr;
       /* *** Extract the 'sin_addr' field from the data type (struct) to obtain a struct 'in_addr' *** */
	
	addr = inet_ntoa(ipaddress->sin_addr);
	

return addr;
}


//f
int main(int argc, char *argv[]){
	
    int port = 7000;	
    char *IP = argv[1];
    int listenfd;
    struct sockaddr_in serv_addr = {0};
    
    /*
     * Si l'IP du serveur n'a pas Ã©tÃ© passÃ©e en argument
     * le programme se termine
     */
    if(argc != 2)
    {
        printf("\n Usage: %s <ip of server> \n",argv[0]);
        return 1;
    }
    /*La socket Cliente */
    printf("[+] Commencer la connexion au port %d ...\n", port);

   
    // CrÃ©ation de la socket
    if((listenfd = socket(AF_INET, SOCK_STREAM, 0))<0) 
    {
        printf("[-] erreur : la socket n'a pas Ã©tÃ© crÃ©Ã© \n");
   
    }
    //applique l'option setoptsocket SO_LINGER
    struct linger so_linger;
    int z;
    so_linger.l_onoff = TRUE;
    so_linger.l_linger = 0;
    z=setsockopt(listenfd ,SOL_SOCKET,SO_LINGER,&so_linger,sizeof so_linger);
    if(z){
  	perror("setsocketopt(2)");
  	}
    
    printf("[+] La socket du port %d est crÃ©e \n",port);  
    //Initialisation de la structure sockaddr
    serv_addr.sin_family = AF_INET;
    //Accepte les connexions depuis n'importe quelle adresse
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    // Le port sur lequel la socket va Ã©couter
    serv_addr.sin_port = htons(port);
    // Copie l'adresse ip du serveur dans la structure serv_addr
    if(inet_pton(AF_INET,IP, &serv_addr.sin_addr)<=0)
    {
        printf("[-] Erreur : net_pton() \n");
    } 

    // Connection au serveur
    if( connect(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("[-] Erreur : Connection au port %d a Ã©tÃ© Ã©chouuÃ©e\n", port);
    }
    
    
    //declaration des variables
     char check[SIZE];
     char *nom_fichier1 = "recv.sh";
     
    
    //inscription dans le serveur
    inscrire(listenfd);
	 

    bzero(&check, SIZE);
    recevoir(listenfd, check);

    //authentification de client
    authentifier(listenfd, check);
    bzero(&check, SIZE);
    //appel la fonction receivfile

    receivefile(nom_fichier1);
    
    
    // fermé la connection sur le port 7000
    close(listenfd);
   //sleep(200);
  //shutdown(listenfd, SHUT_RD);


return 0;
}

