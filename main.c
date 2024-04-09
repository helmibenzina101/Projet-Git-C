#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/evperr.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
char* sha256file(char* file) {
	// Créer un nom de fichier temporaire
	char tempFileName[] = "/tmp/temp_fileXXXXXX";
	int tempFile = mkstemp(tempFileName);
	if (tempFile == -1) {
		perror("Erreur lors de la création du fichier temporaire");
		exit(EXIT_FAILURE);
	}
	
	// Copier le contenu du fichier spécifié vers le fichier temporaire
	FILE* inputFile = fopen(file, "r");
	FILE* tempFilePtr = fdopen(tempFile, "w");
	if (!inputFile || !tempFilePtr) {
		perror("Erreur lors de l'ouverture des fichiers");
		exit(EXIT_FAILURE);
	}
	
	char buffer[1024];
	size_t bytesRead;
	while ((bytesRead = fread(buffer, 1, sizeof(buffer), inputFile)) > 0) {
		fwrite(buffer, 1, bytesRead, tempFilePtr);
	}
	
	fclose(inputFile);
	fclose(tempFilePtr);
	
	// Calculer le hash SHA-256 en utilisant sha256sum
	char command[1024];
	snprintf(command, sizeof(command), "sha256sum %s | awk '{print $1}'", tempFileName);
	FILE* pipe = popen(command, "r");
	if (!pipe) {
		perror("Erreur lors de l'exécution de la commande sha256sum");
		exit(EXIT_FAILURE);
	}
	
	char result[65]; // 64 caractères pour le hash SHA-256 + 1 caractère pour le caractère nul
	fgets(result, sizeof(result), pipe);
	
	// Fermer le pipe
	pclose(pipe);
	
	// Supprimer le fichier temporaire
	remove(tempFileName);
	
	// Allouer de la mémoire pour stocker le résultat
	char* hash = strdup(result);
	if (!hash) {
		perror("Erreur lors de l'allocation de mémoire");
		exit(EXIT_FAILURE);
	}
	
	// Retourner le hash SHA-256
	return hash;
}

void print_errors(const char *function, const char *file, int line) {
	ERR_print_errors_fp(stderr); // Only stderr as the argument
	fprintf(stderr, "Error at %s:%d in %s\n", file, line, function);
}

int hash_file(const char* source, char* dest) {
	EVP_MD_CTX* ctx = EVP_MD_CTX_create();
	const EVP_MD* digest = EVP_get_digestbyname("sha256");
	FILE* file = fopen(source, "rb");
	unsigned char buffer[1024];
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int hash_len;
	
	if (!ctx || !digest || !file) {
		print_errors("EVP_MD_CTX_create, EVP_get_digestbyname, or fopen", __FILE__, __LINE__);
		return 1;
	}
	
	if (!EVP_DigestInit_ex(ctx, digest, NULL)) {
		print_errors("EVP_DigestInit_ex", __FILE__, __LINE__);
		return 1;
	}
	
	while (1) {
		size_t bytes_read = fread(buffer, 1, sizeof(buffer), file);
		if (bytes_read == 0) {
			break; // EOF
		}
		if (!EVP_DigestUpdate(ctx, buffer, bytes_read)) {
			print_errors("EVP_DigestUpdate", __FILE__, __LINE__);
			return 1;
		}
	}
	
	if (!EVP_DigestFinal_ex(ctx, hash, &hash_len)) {
		print_errors("EVP_DigestFinal_ex", __FILE__, __LINE__);
		return 1;
	}
	
	fclose(file);
	EVP_MD_CTX_destroy(ctx);
	
	// Output hash to dest file in hexadecimal format
	FILE* output_file = fopen(dest, "w");
	if (!output_file) {
		perror("fopen dest");
		return 1;
	}
	for (unsigned int i = 0; i < hash_len; i++) {
		fprintf(output_file, "%02x", hash[i]);
	}
	fclose(output_file);
	
	return 0;
}
typedef struct cell {
	char* data;
	struct cell* next;
} Cell;
typedef Cell* List;
List* initList() {
	List* newList = malloc(sizeof(List));
	if (newList == NULL) {
		fprintf(stderr, "Erreur d'allocation mémoire\n");
		exit(EXIT_FAILURE);
	}
	*newList = NULL; // Initialiser la liste vide
	return newList;
}
Cell* buildCell(char* ch) {
	// Allouer de la mémoire pour la nouvelle cellule
	Cell* newCell = malloc(sizeof(Cell));
	if (newCell == NULL) {
		fprintf(stderr, "Erreur d'allocation mémoire\n");
		exit(EXIT_FAILURE);
	}
	
	// Allouer de la mémoire pour copier la chaîne de caractères
	newCell->data = strdup(ch);
	if (newCell->data == NULL) {
		fprintf(stderr, "Erreur d'allocation mémoire\n");
		exit(EXIT_FAILURE);
	}
	
	// Initialiser le pointeur suivant à NULL
	newCell->next = NULL;
	
	// Retourner la nouvelle cellule
	return newCell;
}
void insertFirst(List *L, Cell* C) {
	// Si la liste est vide, assigner la cellule en tant que tête de liste
	if (*L == NULL) {
		*L = C;
	} else {
		// Sinon, mettre la cellule en tête de liste et ajuster les pointeurs
		C->next = *L;
		*L = C;
	}}



char* ctos(Cell* c) {
	if (c == NULL) {
		return NULL;
	}
	return c->data;
}
char* ltos(List* L) {
	if (*L == NULL) {
		return NULL;
	}
	
	// Calcul de la longueur totale de la chaîne
	size_t totalLength = 0;
	Cell* current = *L;
	while (current != NULL) {
		totalLength += strlen(current->data) + 1; // +1 pour le séparateur '|'
		current = current->next;
	}
	
	// Allouer de la mémoire pour la chaîne résultante
	char* result = malloc(totalLength + 1); // +1 pour le caractère nul
	if (result == NULL) {
		fprintf(stderr, "Erreur d'allocation mémoire\n");
		exit(EXIT_FAILURE);
	}
	
	// Construire la chaîne résultante en parcourant la liste
	current = *L;
	size_t index = 0;
	while (current != NULL) {
		size_t len = strlen(current->data);
		strncpy(result + index, current->data, len);
		index += len;
		result[index++] = '|'; // Ajouter le séparateur '|'
		current = current->next;
	}
	result[index - 1] = '\0'; // Remplacer le dernier '|' par le caractère nul
	
	return result;
}
Cell* listGet(List* L, int i) {
	if (*L == NULL || i < 0) {
		return NULL; // Si la liste est vide ou si l'index est invalide, retourner NULL
	}
	
	Cell* current = *L;
	int index = 0;
	
	// Parcourir la liste jusqu'à l'élément désiré
	while (current != NULL && index < i) {
		current = current->next;
		index++;
	}
	
	// Si l'index est supérieur à la taille de la liste, retourner NULL
	if (index != i || current == NULL) {
		return NULL;
	}
	
	// Sinon, retourner l'élément trouvé
	return current;
}
Cell* searchList(List* L, char* str) {
	if (*L == NULL || str == NULL) {
		return NULL; // Si la liste est vide ou si la chaîne est NULL, retourner NULL
	}
	
	Cell* current = *L;
	
	// Parcourir la liste
	while (current != NULL) {
		// Comparer le contenu de la cellule avec la chaîne donnée
		if (strcmp(current->data, str) == 0) {
			return current; // Si la chaîne est trouvée, retourner la cellule
		}
		current = current->next;
	}
	
	// Si la chaîne n'est pas trouvée dans la liste, retourner NULL
	return NULL;
}
List* stol(char* s) {
	List* head = initList(); // Initialiser la liste
	
	char* token = strtok(s, "|"); // Utiliser '|' comme délimiteur
	while (token != NULL) {
		Cell* new_cell = buildCell(token); // Créer une nouvelle cellule avec le token
		insertFirst(head, new_cell); // Insérer la nouvelle cellule en tête de liste
		token = strtok(NULL, "|"); // Passage au token suivant
	}
	
	return head; // Retourner la tête de liste
}
void ltof(List* L, char* path) {
	FILE* file = fopen(path, "w");
	if (file == NULL) {
		fprintf(stderr, "Erreur lors de l'ouverture du fichier %s\n", path);
		exit(EXIT_FAILURE);
	}
	
	Cell* current = *L;
	while (current != NULL) {
		fprintf(file, "%s|", current->data);
		current = current->next;
	}
	
	fclose(file);
}

List* ftol(char* path) {
	FILE* file = fopen(path, "r");
	if (file == NULL) {
		fprintf(stderr, "Erreur lors de l'ouverture du fichier %s\n", path);
		exit(EXIT_FAILURE);
	}
	
	List* newList = malloc(sizeof(List));
	if (newList == NULL) {
		fprintf(stderr, "Erreur d'allocation mémoire\n");
		exit(EXIT_FAILURE);
	}
	*newList = NULL;
	
	char buffer[256];
	while (fgets(buffer, sizeof(buffer), file) != NULL) {
		char* token = strtok(buffer, "|");
		while (token != NULL) {
			Cell* newCell = malloc(sizeof(Cell));
			if (newCell == NULL) {
				fprintf(stderr, "Erreur d'allocation mémoire\n");
				exit(EXIT_FAILURE);
			}
			newCell->data = strdup(token);
			newCell->next = *newList;
			*newList = newCell;
			token = strtok(NULL, "|");
		}
	}
	
	fclose(file);
	return newList;
}
List* listdir(char* root_dir) {
	DIR* dp = opendir(root_dir);
	if (dp == NULL) {
		perror("Erreur lors de l'ouverture du répertoire");
		exit(EXIT_FAILURE);
	}
	
	List* fileList = initList(); // Initialisation de la liste vide
	struct dirent* entry;
	
	while ((entry = readdir(dp)) != NULL) {
		// Création d'une nouvelle cellule avec le nom du fichier/dossier
		Cell* newCell = buildCell(entry->d_name);
		// Insertion de la cellule en tête de liste
		insertFirst(fileList, newCell);
	}
	
	closedir(dp);
	return fileList;
}
int file_exists(char *file) {
	// Obtention de la liste des fichiers dans le répertoire courant
	List* fileList = listdir(".");
	Cell* current = *fileList;
	
	// Parcours de la liste pour vérifier si le fichier existe
	while (current != NULL) {
		if (strcmp(current->data, file) == 0) {
			// Le fichier a été trouvé dans le répertoire courant
			// Libération de la mémoire allouée pour la liste et ses éléments
			while (*fileList != NULL) {
				Cell* temp = *fileList;
				*fileList = (*fileList)->next;
				free(temp->data); // Libération de la mémoire allouée pour la chaîne de caractères
				free(temp);       // Libération de la mémoire allouée pour la cellule
			}
			free(fileList);
			return 1; // Le fichier existe
		}
		current = current->next;
	}
	
	// Libération de la mémoire allouée pour la liste et ses éléments
	while (*fileList != NULL) {
		Cell* temp = *fileList;
		*fileList = (*fileList)->next;
		free(temp->data); // Libération de la mémoire allouée pour la chaîne de caractères
		free(temp);       // Libération de la mémoire allouée pour la cellule
	}
	free(fileList);
	
	// Le fichier n'a pas été trouvé dans le répertoire courant
	return 0;
}
void cp(char *to, char *from) {
	// Ouvrir le fichier source en lecture
	FILE *source = fopen(from, "r");
	if (source == NULL) {
		fprintf(stderr, "Erreur : Impossible d'ouvrir le fichier source %s\n", from);
		return;
	}
	
	// Ouvrir le fichier destination en écriture
	FILE *destination = fopen(to, "w");
	if (destination == NULL) {
		fprintf(stderr, "Erreur : Impossible d'ouvrir le fichier destination %s\n", to);
		fclose(source);
		return;
	}
	
	// Copie ligne par ligne
	char buffer[1024];
	while (fgets(buffer, sizeof(buffer), source) != NULL) {
		fputs(buffer, destination);
	}
	
	// Fermer les fichiers
	fclose(source);
	fclose(destination);
	
	printf("Copie du fichier terminée avec succès.\n");
}
char* hashToPath(char* hash) {
	// Vérifier si le hash est valide (de longueur au moins 3)
	if (strlen(hash) < 3) {
		printf("Erreur : Hash invalide.\n");
		return NULL;
	}
	
	// Allouer de la mémoire pour le chemin résultant
	char* path = (char*)malloc((strlen(hash) + 2) * sizeof(char)); // +2 pour le '/' et le caractère nul
	
	// Construire le chemin en insérant '/' entre le deuxième et le troisième caractères du hash
	strncpy(path, hash, 2); // Copier les deux premiers caractères
	path[2] = '/'; // Insérer '/'
	strncpy(path + 3, hash + 2, strlen(hash) - 2); // Copier le reste du hash
	path[strlen(hash) + 1] = '\0'; // Ajouter le caractère nul à la fin
	
	return path;
}
void blobFile(char* file) {
	char command[512]; // Chaîne pour stocker la commande shell
	char dirname[512]; // Nom du répertoire de destination
	
	// Vérifier si le fichier existe
	FILE *fp = fopen(file, "r");
	if (fp == NULL) {
		printf("Erreur : Le fichier %s n'existe pas.\n", file);
		return;
	}
	fclose(fp);
	
	// Créer un répertoire "snapshots" s'il n'existe pas déjà
	if (system("[ -d snapshots ] || mkdir snapshots") != 0) {
		printf("Erreur lors de la création du répertoire snapshots.\n");
		return;
	}
	
	// Obtenir le nom du fichier sans le chemin
	char *filename = strrchr(file, '/');
	if (filename == NULL) // Pas de slash, donc le nom du fichier est le nom complet
		filename = file;
	else // Si le nom du fichier contient un slash, on prend la partie après le dernier slash
		filename++;
	
	// Construire le nom du répertoire de destination
	sprintf(dirname, "snapshots/%s_snapshot_$(date +%%Y%%m%%d_%%H%%M%%S)", filename);
	
	// Créer le répertoire de destination
	sprintf(command, "mkdir -p \"%s\"", dirname);
	if (system(command) != 0) {
		printf("Erreur lors de la création du répertoire de destination.\n");
		return;
	}
	
	// Construire la commande pour copier le fichier dans le répertoire snapshots
	sprintf(command, "cp \"%s\" \"%s/%s\"", file, dirname, filename);
	
	// Exécuter la commande shell
	if (system(command) != 0) {
		printf("Erreur lors de la copie du fichier %s.\n", file);
		return;
	}
	
	printf("Instantané du fichier %s enregistré.\n", file);
}


int main() {
	system("ls");
	int result = hash_file("/home/helmi/projetscv/main.c", "/home/helmi/projetscv/main.tmp");
	if (result != 0) {
		fprintf(stderr, "Error: Hashing failed\n");
		
	}
	printf("Hashing successful!\n");
	
	
	char *hash = sha256file("/home/helmi/projetscv/main1.c");
	printf("proceed with hash");
	
	if (hash != NULL) {
	
		printf("Hash: %s\n", hash);
		free(hash); // Remember to free the allocated memory after use
		
	} else {
		fprintf(stderr, "Error: Could not calculate hash\n");
	}
// Initialisation de la liste vide
	List* maliste = initList();
	
	// Ajout d'un élément à la liste
	Cell* newCell = malloc(sizeof(Cell));
	if (newCell == NULL) {
		fprintf(stderr, "Erreur d'allocation mémoire\n");
		exit(EXIT_FAILURE);
	}
	newCell->data = "Premier élément";
	newCell->next = NULL;
	
	// Liaison du nouvel élément à la liste
	insertFirst(maliste, newCell);
	
	// Parcours de la liste et affichage des éléments
	Cell* current = *maliste;
	while (current != NULL) {
		printf("%s\n", current->data);
		current = current->next;
	}
	
	// Libération de la mémoire allouée pour la liste et ses éléments
	current = *maliste;
	while (current != NULL) {
		Cell* temp = current;
		current = current->next;
		free(temp);
	}
	free(maliste);
	char* myString = "test 1";
	Cell* myCell = buildCell(myString);
	
	// Affichage du contenu de la cellule
	printf("Contenu de la cellule : %s\n", myCell->data);
	
	// Libération de la mémoire allouée pour la cellule
	free(myCell->data); // Libérer d'abord la chaîne de caractères allouée par strdup
	free(myCell);
	// Création de quelques cellules pour former une liste
	Cell cell1 = {"Donnée 1", NULL};
	Cell cell2 = {"Donnée 2", NULL};
	Cell cell3 = {"Donnée 3", NULL};
	
	// Initialisation d'un pointeur de liste pour pointer vers la tête de la liste
	List myList = NULL;
	
	// Insertion des cellules en tête de liste pour former la liste
	insertFirst(&myList, &cell3);
	insertFirst(&myList, &cell2);
	insertFirst(&myList, &cell1);
	
	// Utilisation de la fonction ltos pour convertir la liste en une chaîne de caractères
	char* resultat = ltos(&myList);
	
	// Affichage du résultat
	if (resultat != NULL) {
		printf("Résultat : %s\n", resultat);
		free(resultat); // Libérer la mémoire allouée pour le résultat
	} else {
		printf("La liste est vide.\n");
	}
	 int indexToRetrieve = 2;
	Cell* retrievedCell = listGet(&myList, indexToRetrieve);
	
	if (retrievedCell != NULL) {
		printf("L'élément à l'index %d est : %s\n", indexToRetrieve, retrievedCell->data);
	} else {
		printf("L'élément à l'index %d n'existe pas dans la liste.\n", indexToRetrieve);
	}
	char* strToFind = "Donnée 1";
	Cell* foundCell = searchList(&myList, strToFind);
	
	if (foundCell != NULL) {
		printf("L'élément \"%s\" a été trouvé dans la liste.\n", strToFind);
	} else {
		printf("L'élément \"%s\" n'a pas été trouvé dans la liste.\n", strToFind);
	}
	char s[] = "1|2|3|4|5"; // Chaîne représentant la liste d'entiers
	List* myList5 = stol(s); // Convertir la chaîne en liste chaînée
	
	// Parcourir la liste et afficher ses éléments
	Cell* courant = *myList5;
	while (courant != NULL) {
		printf("%s\n", courant->data);
		courant = courant->next;
	}
	
	// Libérer la mémoire allouée pour la liste
	courant = *myList5;
	while (courant != NULL) {
		Cell* temp = courant;
		courant = courant->next;
		free(temp);
	}
	free(myList5);
	List* newList6 = ftol("/home/helmi/projetscv/a");
	
	// Affichage de la liste lue
	Cell* current1 = *newList6;
	while (current1 != NULL) {
		printf("%s\n", current1->data);
		current1 = current1->next;
	}
	 ltof(newList6,"/home/helmi/projetscv/b");
	List* fileList = listdir("/home/helmi/projetscv"); // chemin specifié
	
	printf("Contenu du répertoire :\n");
	Cell* current2 = *fileList;
	while (current2 != NULL) {
		printf("%s\n", current2->data);
		current2 = current2->next;
	}
	
	if (file_exists("abc")==1)
	{
		printf("le fichier existe\n");
	}
	else
	{
		printf("erreur");
	}
     cp("/home/helmi/projetscv/dest","/home/helmi/projetscv/source");
	char hash2[] = "a1b2c3d4e5f6";
	
	char* path = hashToPath(hash2);
	if (path != NULL) {
		printf("Chemin : %s\n", path);
		free(path); // Libérer la mémoire allouée pour le chemin
	}

	char filename3[] = "aac";
	blobFile(filename3);
		return 0;
}



