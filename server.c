/***********************************************************************************
 *
 * Author: mouhssine el idrissi, youssef el bab
 * Professor: Dr. Briffaut Jeremy, 
 * Creation Date: 02 Mars 2022
 * Due Date: 09 Juin 2022
 * Assignment: server client application
 * Filename: server.c
 * Purpose: allow a server to get scan all the information of client,get his adress IP,
 send file and excute them.
 * compile: make server
 * Run: ./server
 *
 **********************************************************************************/ 
//server.c
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
char * authenfier_pwd_ip(char *ip, char *pwd);
char * compare_ip(char* ip_recu);
void recevoir(int connfd, char* buffer);
void envoyer(int connfd, char* buffer);
void inscrir(int sock);
char* generer_sha1(char* fichier);
FILE* ouvrir_fichier(char* nom_fichier, char*option);
void sendfile(char *ip, char *filename);
char * loadFile(char *name, char  *fileBuff);
/*******************************************/

//la fonction  sendfile
void sendfile(char *ip, char *filename){
 int port = 7001;	
    char *IP = ip;
    int listenfd;
    struct sockaddr_in serv_addr = {0};
 
    // CrÃ©ation de la socket
    if((listenfd = socket(AF_INET, SOCK_STREAM, 0))<0) 
    {
        printf("[-] erreur : la socket n'a pas Ã©tÃ© crÃ©Ã© \n");
   
    }
    //applique l'option setoptsocket SO_LINGER
    struct linger so_linger;
    int z;
    so_linger.l_onoff = 1;
    so_linger.l_linger = 0;
    z=setsockopt(listenfd ,SOL_SOCKET,SO_LINGER,&so_linger,sizeof so_linger);
    if(z){
  	perror("setsocketopt(2)");
  	}
    
    printf("[+] La socket du port %d est crÃ©e \n",port);  
    //Initialisation de la structure sockaddr
    serv_addr.sin_family = AF_INET;
    //Accepte les connexions depuis client qui ouvre viens juste de se connecter
  serv_addr.sin_addr.s_addr = inet_addr(ip);
    // Le port sur lequel la socket va Ã©couter
    serv_addr.sin_port = htons(port);
   
    // Connection au serveur
    if( connect(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("[-] Erreur : Connection au port %d a Ã©tÃ© Ã©chouuÃ©e\n", port);
    }
    
    printf("[+] La connexion au serveur sur le  port %d est effectuee\n",port);
    
    //envoyer le résultat de la fonction d'hachage du fichier avant de l'envoyer
    char sha1[SIZE];
    bzero(&sha1, SIZE);
    strcpy(sha1, generer_sha1(filename));
    envoyer(listenfd,sha1);
    
    //load data from file send.sh and send it to client
    char contenu_file[SIZE];
    bzero(&contenu_file, SIZE);
    strcpy(contenu_file, loadFile(filename,contenu_file));
    envoyer(listenfd, contenu_file);
    bzero(&contenu_file, SIZE);
    
    
    
    //fermé la connection sur le port 7001
    // close(listenfd);
    sleep(100);
    shutdown(listenfd, SHUT_RD);
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

//function de authentification dans liste client
char * authenfier_pwd_ip(char *ip, char *pwd){

	int found = 0;
	char * ok = NULL;
	FILE* fichier = fopen("ListClient.txt","a+");
	char chaine[SIZE];
	bzero(chaine,SIZE);
	const char separateur[2]=":";
	char *token;
	char *etat_password = "Mot de passe valide\n";
	if(fichier!= NULL){
	// récupérer les @ip enregitrees dans ListClient.txt
	while(fgets(chaine,sizeof(chaine),fichier) != NULL){
				token = strtok(chaine,separateur);
				int result = strcmp(ip, token);
				token = strtok(NULL, separateur);
				if(result==0){
					found =1 ;
					ok="valide";
					printf("le mot de passe est :%s\n", pwd);
					strcat(pwd, "\n\0"); 
					int etat = strcmp(token, pwd);
					printf("\n la valeur de test est: %d  \n", etat);
					printf("\n valuer de token est : %s \n", token);
					if(etat == 0) {printf("%s", etat_password);}
					else{ etat_password ="Mot de passe invalide\n";}
					break;
		}//fin if
	}//fin while
	if(!found){
		fputs(ip,fichier);
		fputs(separateur, fichier);
		fputs(pwd, fichier);
		fputs("\n", fichier);
	printf("[+] le client a été bien enregistré\n");
		ok="nvalide";
				}
	fclose(fichier);
	}
return etat_password;
}


//function comparsion de ip dan listeClient

char * compare_ip(char* ip_recu){
	int found = 0;
	char * ok = NULL;
	printf("[+] lire et ajouter l' @ip recu au fichier ListClient.txt...\n");
	FILE* fichier = fopen("ListClient.txt","a+");
	char chaine[SIZE];
	bzero(chaine,SIZE);
	const char separateur[2]=":";
	char *token;
	if(fichier!= NULL){
	// récupérer les @ip enregitrees dans ListClient.txt
	while(fgets(chaine,sizeof(chaine),fichier) != NULL){
				token = strtok(chaine,separateur);
				int result = strcmp(ip_recu, token);
				if(result==0){
					printf("[+] le client existe déjà dans la liste des clients\n");
					found=1;
					ok="valide";
					break;
		}//fin if
	}//fin while
	if(!found){
		//fputs(ip_recu,fichier);
		//printf("[+] le client a été bien enregistré\n");
		ok="nvalide";
				}
	fclose(fichier);
	}
return ok;
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

/*###################################################################################################################*/



// la fonction main//

int main(int argc, char *argv[])
{
    int port = 7000;
    int listenfd;
     // La structure avec les informations du serveur
    struct sockaddr_in serv_addr = {0};
    
    printf("[+] Création de la socket Serveur du port %d...\n",port);
    
    // Création de la socket serveur
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if(listenfd<0){
	    perror("[-] Erreur: la socket ne peut pas etre crée \n");
    }
    printf("[+] la socket a été bien crée \n");
    //applique l'option setoptsocket SO_LINGER
    struct linger so_linger;
    int z;
    so_linger.l_onoff = 1;
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
  
   char *check;
   char pwd[SIZE];
   char client_ip[SIZE];
  
   while(1)
    {
        // Accepte la connexion d'une socket client
	printf("[+] Acceptation de la connexion au port %d\n",port);
        int connfd = accept(listenfd, (struct sockaddr*)NULL, NULL);
        
        //reception de l'@ip du client
     	recevoir(connfd, client_ip);
       
       	//comparaison de l'@ip recu avec les @ip de la liste existante
       	 check= compare_ip(client_ip);
	 envoyer(connfd, check);
         bzero(&pwd, SIZE);
	 recevoir(connfd, pwd);
	 char  etat_pass[SIZE];
	 bzero(&etat_pass, SIZE);
	 strcpy(etat_pass, authenfier_pwd_ip(client_ip, pwd));
	 envoyer(connfd, etat_pass);
	 bzero(&etat_pass, SIZE);
	 
       //envoyer le résultat de la fonction d'hachage du fichier avant de l'envoyer
	char *nom_fichier1 = "send.sh";
       
       //appel function sendfile sur le port 7001
         sendfile(client_ip, nom_fichier1);
       
       
       //fermé la conncetion de server
       	
	//close(connfd);
	sleep(100);
       shutdown(connfd, SHUT_RD);
        }

  
return 0;

}
