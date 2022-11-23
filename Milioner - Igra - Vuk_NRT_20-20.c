//Vuk Aranđelović NRT-20/20
//Komentari i napomene:
//Za pisanje ovog programa sam koristio Visual Studio Code kompajler, to je okruzenje na koje sam navikao.
//Trebalo bi da sve radi kako treba i u VS2010, ali ne mogu biti potpuno siguran.
//historydefault.txt se ne koristi u programu, vec sluzi kao template za praznu listu istorija.txt, ukoliko je potrebno resetovanje liste radi odbrane/testiranja, samo se iskopira lista i nema potrebe za prekucavanjem
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> //koristi se kako bi nasumicne funkcije mogle raditi kako treba

#define PIT_SIZE 201
#define ODG_SIZE 56

//opis svake funkcije i cemu sluzi
/* ==========       START  --  FUNKCIJE-Define   ========== */
void mainMenu(int);                             //glavni meni iz kojeg se pokrecu glavne funkcije programa, prosledjuje se integer iz main-a (int k) koji se ne koristi nigde vec se prosledjuje funkciji printMilioner
void printMilioner(int);                        //prosledjuje joj se int k iz mainMenu, koji sluzi kao fleg, ukoliko je fleg 1 stampace se polako, medjutim to je slucaj samo jednom i to nakon prvog pokretanja programa
void uputstvoMenu();                            //ispisuje uputstvo i ceka odgovarajuci unos za izlaz iz uputstva
void uputstvo();                                //funkcija koja postoji kako bi uputstvoMenu izgledao urednije, u sustini cela 'skripta' uputstva
void podesavanja();                             //ovde se konfigurise globalna promenljiva linuxOS, koja menja odredjene stvari u programu tako da rade i na tom OS-u (uglavnom vizuelne stvari, Milioner naslov se stampa drugacije i ciscenje konzole zahteva drugaciji argument)
void upisIstorija(int, char *);                 //koristi se na kraju svake igre, prosledjuju joj se broj tacnih odgovora i memorijska lokacija niza sa imenom igraca iz funkcije igra, preuredjuje datoteku istorija.txt tako da prikazuje poslednja 15 pokusaja ukljucujuci taj koj se upravo zavrsio
void istorija();                                //istorija poslednjih 15 pokusaja sa brojem tacno uradjenih pitanja i imenom igraca
void uzimanje();                                //sluzi za otvaranje datoteke sa pitanjima i ucitavanje 5 nasumicno odabranih jedinstvenih pitanja iz iste. Bira datoteku koristeci globalnu promenljivu tezina
void igra();                                    //ova funkcija pokrece proces igre/kviza, 2 for petlje, prva generise 5 pitanja iz datoteke trazene kategorije, povecava kategoriju i proverava uslove za kraj igre, druga postavlja igracu ta 5 pitanja i proverava da li je odgovor tacan
void stampanjePitanja(int, int, char *);        //funkcija za stampanje pitanja, prosledjuju se indexi obe for petlje funkcije igra (da bi se izracunao broj pitanja) i pointer na odgovor koji korisnik unosi (original se nalazi u funkciji igra)
void pomoc(int, int, char *);                   //ova funkcija nudi korisniku dostupne pomoci i ceka odabir, sa mogucnoscu vracanja u pitanje bez koriscenja pomoci (ako se korisnik predomisli pre uzimanja pomoci)
void pomoc5050(int, int, char *);               //ukoliko se izabere pomoc5050, broj pitanja se prosledjuje i ucitava se odgovarajuce pitanje, zatim se obradjuje korisnikov unos, koji se vraca nazad u igru na proveru
void pomocPrijatelja(int, int, char *);         //kod slucaja pomocPrijatelja, broj pitanja i odgovori se posledjuju jer su potrebni ponovo u printPitanjeNakonPomoci, a broj pitanja se koristi za generisanje tacnog odgovora/pomaganje korisnike
void pomocPublike(int, int, char *);            //pomocPublike radi vrlo slicno kao i pomocPrijatelja sa tim sto je drugacije realizovano i prikazano
void printPitanjeNakonPomoci(int, int, char *); //printPitanjeNakonPomoci u sustini radi isto kao i stampanjePitanja sa tim sto ne dozvoljava korisniku da pristupi pomocima ponovo, da ne bi koristio sve pomoci na jedno pitanje
//zadnje 6 funkcije imaju prosledjene iste argumente jer su medjusobno povezane
/* ==========         END  --  FUNKCIJE-Define  ========== */

/* ==========       START  --  GLOBAL   ========== */
short pu = 178;         //ASCII za punu kocku
short pr = 176;         //ASCII za praznu kocku
short brojPitanja = 12; //pamti broj pitanja po kategorijama, moze se menjati u slucaju vece baze sa pitanjima
short tezina = 0;       //brojac koji odredjuje koja kategorija pitanja se ucitava      0 - Easy  (prva 5 pitanja)   1 - Medium   (druga 5 pitanja)     2 - Hard   (poslednja 5 pitanja)
short _5050 = 1;        //flag - da li korisnik trenutno ima pomoc 50/50
short _pPrijatelja = 1; //flag - da li korisnik trenutno ima pomoc prijatelja
short _pPublike = 1;    //flag - da li korisnik trenutno ima pomoc publike
short linuxOS = 0;      //flag koji treba promeniti u zavisnosti od sistema na kom je pokrenuta aplikacija, sluzi za vizualne funkcionalnosti
/* ==========         END  --  GLOBAL   ========== */

/* ==========       START  --  STRUKTURE  ========== */
typedef struct
{
    char pitanje[PIT_SIZE]; //pamti celo pitanje
    char a[ODG_SIZE];       //pamti ceo odgovor a
    char b[ODG_SIZE];       //pamti ceo odgovor b
    char c[ODG_SIZE];       //pamti ceo odgovor c
    char d[ODG_SIZE];       //pamti ceo odgovor d
    char o;                 // pamti tacan odgovor
} pitanje;

pitanje *pitanja;
/* ==========         END  --  STRUKTURE  ========== */

//Kod svake funkcije u programu. Unutar svake funkcije je redom opisano sta cemu sluzi. Opisi samih funkcija se nalaze na istom mestu gde su definisane
/* ==========       START  --  FUNKCIJE-Code       ========== */
int main()
{
    pitanja = malloc(sizeof(pitanje) * 5); //dinamicka dodela memorije za 5 pitanja

    int k = 1; // promenljiva koja sluzi za ukras, odnosno sporo ucitavanje logoa milioner pri prvom pokretanju
    while (1)
    {
        //setovanje flagova pri svakom ponovnom poketanju mainMenu, odnosno po svakom zavrsetku igre
        tezina = 0;
        _5050 = 1;
        _pPrijatelja = 1;
        _pPublike = 1;
        mainMenu(k);
        k = 0; //nakon prve instance while petlje se k menja u 0, i svako slede pokretanje mainMenu ce biti instant
    }

    return 0;
}

void mainMenu(int k)
{
    system(linuxOS ? "clear" : "cls"); //cisti ekran da se ne bi gomilao unos i ispis tokom koriscenja
    printMilioner(k);
    printf("\nDobrodosli na kviz \"Da li zelite da postanete milioner?\"\n\n\t1. Pokreni igru\n\t2. Uputstvo\n\t3. Podesavanja\n\t4. Rang lista\n\t0. Izlaz\n\n");

    int meni;
    fflush(stdin);
    scanf("%i", &meni);
    fflush(stdin);
    while ((meni > 4) || (meni < 0))
    {
        system(linuxOS ? "clear" : "cls");
        printMilioner(0);
        printf("\nDobrodosli na kviz \"Da li zelite da postanete milioner?\"\n\n\t1. Pokreni igru\n\t2. Uputstvo\n\t3. Podesavanja\n\t4. Rang lista\n\t0. Izlaz\n\n");
        printf("\nIzabrana opcija ne postoji. Pokusajte ponovo: ");
        scanf("%i", &meni);
        fflush(stdin);
    }

    switch (meni)
    {
    case 0:
        printf("\nHvala na igranju! Dovidjenja!");
        exit(0);
        break;
    case 1:
        igra();
        break;
    case 2:
        uputstvoMenu();
        break;
    case 3:
        podesavanja();
        break;
    default:
        istorija();
        break;
    }
}

void printMilioner(int k)
{
    short map[7][64] = {
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0},
        {0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0},
        {0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0},
        {0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0},
        {0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};

    // ovo je mapa naslova igrice, koja se stampa kroz vecinu aplikacije
    struct timespec tim;   //struktura koja pamti sekunde i nanosekunde za koje se sleepuje
    tim.tv_sec = 0;        //sekunde
    tim.tv_nsec = 1000000; //nanosekunde

    for (int i = 1; i < 65; i++)
    {
        printf("=");
    }
    printf("\n");
    for (int i = 0; i < 7; i++)
    {
        for (int j = 0; j < 64; j++)
        {
            if (map[i][j] == 1)
            {
                if (linuxOS == 1)
                    printf("\u2593");
                else
                    printf("%c", pu);
            }
            else
            {

                if (linuxOS == 1)

                    printf("\u2591");
                else
                    printf("%c", pr);
            }
            if (k == 1)
                nanosleep(&tim, 0); //Komanda koja pauzira rad programa na zadato vreme i samim tim daje prividni izgled "ucitavanja", dodato radi estetike
        }
        printf("\n");
    }
    for (int i = 1; i < 65; i++)
    {
        printf("=");
    }
    printf("\n");
}

void uputstvoMenu()
{
    system(linuxOS ? "clear" : "cls");
    printMilioner(0);
    uputstvo(); // poziv funkcije koja stampa uputstvo, radi preglednosti

    int meni;
    scanf("%i", &meni);
    fflush(stdin);
    while (meni != 0)
    {
        system(linuxOS ? "clear" : "cls");
        printMilioner(0);
        uputstvo();
        printf("\nIzabrana opcija ne postoji. Pokusajte ponovo: ");
        scanf("%i", &meni);
        fflush(stdin);
    }
}

void uputstvo()
{
    printf("\nOpis programa i uputstvo za koriscenje:\n\nMilioner je igra u kojoj je cilj da se da tacan odgovor na svih 15 pitanja.");
    printf("\nPitanja imaju 4 ponudjena odgovora od kojih je samo jedan tacan!");
    printf("\nUkoliko niste sigurni koji odgovor je tacan, postoje 3 vrste pomoci koje mozete da iskoristite i povecate sansu da budete pobednik!");
    printf("\nMedjutim, veoma je bitno zapamtiti da svaku pomoc mozete iskoristiti samo jednom u toku igre, i to samo jednu pomoc po pitanju!\n");
    printf("\n\tVrste pomoci:");
    printf("\n\t1. 50:50 - Uklanja dva netacna odgovora i ostavlja samo jedan netacan i jedan tacan odgovor.");
    printf("\n\t2. Pomoc prijatelja - Mogucnost da pozovete jednog prijatelja kako bi vam rekao koji odgovor je tacan. ( Pazite se, prijatelji nisu uvek u pravu! ;) )");
    printf("\n\t3. Pomoc publike - Publika ce vam reci za koji odgovor misle da je tacan. ( Koje su sanse da vecina publike pogresi na pitanje...? :) )");
    printf("\n\nNa pocetku igre unosite svoje ime, koje ce se prikazivati sa ostalim pokusajima u istoriji pokusaja.");
    printf("\nBitno je napomenuti da kod unosenja izbora upisete opciju bas tako kako je navedena.\n(Ako je ponudjena opcija 'A', unos 'a' nece biti prihvacen!)");
    printf("\n\n\t\t\t\t\t\t\t\t\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    printf("\n\t\t\t\t\t\t\t\t\t! Napomena:\t\t\t\t  !\n\t\t\t\t\t\t\t\t\t! Ukoliko koristite OS Linux,\t\t  !\n\t\t\t\t\t\t\t\t\t! ukljucite Linux opciju u podesavanjima! !");
    printf("\n\t\t\t\t\t\t\t\t\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    printf("\n0. Povratak u meni\n");
    //komentar :)
}

void podesavanja()
{
    while (1) //petlja se vrti dok god nije pritisnuta 0
    {
        system(linuxOS ? "clear" : "cls");
        printMilioner(0);
        printf("\nPodesavanja:\n\n\t1. Linux operativni sistem:\t%s\t\t(Ukljucite ako koristite LinuxOS)", linuxOS ? "true" : "false"); //prikazuje trenutno stanje flag-a iz globalnih
        printf("\n\n\t0. Izlaz iz podesavanja\t\t");

        int meni;
        scanf("%i", &meni);
        fflush(stdin);

        while (meni != 0 && meni != 1)
        {
            system(linuxOS ? "clear" : "cls");
            printMilioner(0);
            printf("\nPodesavanja:\n\n\t1. Linux operativni sistem:\t%s\t\t(Ukljucite ako koristite LinuxOS)", linuxOS ? "true" : "false");
            printf("\n\n\t0. Izlaz iz podesavanja\t\t");
            printf("\nIzabrana opcija ne postoji. Pokusajte ponovo: ");

            fflush(stdin);
            scanf("%i", &meni);
            fflush(stdin);
        }

        if (meni == 1) //ukoliko je pritisnuto dugme za menjanje podesavanja, obrce se vrednost flag-a
            linuxOS = !linuxOS;
        else
            break;
    }
}

void upisIstorija(int tacni, char *ime)
{
    //prosledjene vrednosti su adresa na kojoj se nalazi upisano ime igraca poslednjeg (trenutnog - sto se tice vremena poziva ove funkcije) pokusaja i broj tacnih odgovora
    FILE *file; // otvaranje datoteke za citanje
    file = fopen("istorija.txt", "r");
    if (file == NULL)
    {
        printf("\n\tGreska pri otvaranju fajla \"istorija.txt\". (file = NULL - upisIstorija())\n");
        exit(1);
    }
    char imeTmp[15][33];    //niz stringova velicine imena
    strcpy(imeTmp[0], ime); //pamti se ime trenutnog pokusaja u prvu lokaciju u nizu
    int tacniTmp[15];
    tacniTmp[0] = tacni; //pamti se broj tacnih odgovora trenutnog pokusaja na prvu lokaciju u nizu
    printf("__|[Broj tacnih odgovora]|_______[Ime]______\n");
    for (int i = 1; i < 15; i++) //petlja pocinje od 1 radi lakseg pristupa gore-navedenim nizovima, 0. lokacija je vec iskoriscena
    {                            //petlja ima 14 iteracija jer se u istorijatu pamte poslednja 15 pokusaja, trenutni i prethodna 14
        char tmp[33];
        fgets(tmp, 33, file);
        strcpy(imeTmp[i], tmp);
        fscanf(file, "%i ", &tacniTmp[i]);
    }

    fclose(file); //zatvaranje datoteke

    file = fopen("istorija.txt", "w"); //ponovno otvaranje datoteke, ovoga puta u write modu kako bi obrisao sve podatke iz datoteke
    if (file == NULL)                  //nisam siguran da li moze doci do ove greske uopste, jer write mode kreira novu datoteku sa datim imenom ukoliko ne nadje istu... ali sam ostavio za svaki slucaj
    {
        printf("\n\tGreska pri otvaranju fajla \"istorija.txt\". (file = NULL - upisIstorija())\n");
        exit(1);
    }
    for (int i = 0; i < 15; i++) //upis nizova u datoteku
    {
        if (i == 0)
            fprintf(file, "%s\n", imeTmp[i]);
        else
            fprintf(file, "%s", imeTmp[i]);
        fprintf(file, "%i\n", tacniTmp[i]);
    }
    fclose(file); //zatvaranje datoteke
}

void istorija()
{
    FILE *file; //otvaranje datoteke za citanje
    file = fopen("istorija.txt", "r");
    if (file == NULL)
    {
        printf("\n\tGreska pri otvaranju fajla \"istorija.txt\". (file = NULL)\n");
        exit(1);
    }

    system(linuxOS ? "clear" : "cls");
    printMilioner(0);
    printf("\n\tDobrodosli u istorijat pokusaja Milioner kviza:\n\n");

    char imeTmp[33];
    int tacniTmp, izlaz;
    printf("\t__|[Broj tacnih odgovora]|______[Ime]__________\n");
    for (int i = 0; i < 15; i++) // petlja koja stampa istorijat
    {
        fgets(imeTmp, 33, file);
        fscanf(file, "%i ", &tacniTmp);
        if (tacniTmp == 1)
            printf("\t%i:\t%i Pitanje\t |\t%s", i + 1, tacniTmp, imeTmp);
        else
            printf("\t%i:\t%i Pitanja\t |\t%s", i + 1, tacniTmp, imeTmp);
    }
    printf("\t_______________________________________________\n");
    printf("\n\n\t\t0. Izlaz iz istorijata.\t");
    scanf("%i", &izlaz);
    fflush(stdin);
    while (izlaz != 0) // petlja za validan unos
    {
        printf("\nIzabrana opcija ne postoji. Pokusajte ponovo: ");
        scanf("%i", &izlaz);
        fflush(stdin);
    }

    fclose(file); //zatvaranje datoteke po izlasku iz funkcije
}
//MAIN MENU END - GAME BEGIN
void uzimanje()
{
    time_t t;                  //setuje promenljivu t na trenutno vreme
    srand((unsigned)time(&t)); //podesava seed (seme) za random commandu koristeci trenutno vreme

    char imeFajla[30];
    FILE *fajl = NULL;
    switch (tezina) // biranje datoteke u odnosu na zeljenu tezinu
    {
    case 0:
        strcpy(imeFajla, "EPitanja.txt");
        break;
    case 1:
        strcpy(imeFajla, "MPitanja.txt");
        break;
    case 2:
        strcpy(imeFajla, "HPitanja.txt");
        break;
    }
    fajl = fopen(imeFajla, "r");

    if (fajl == NULL) //error poruka ukoliko je nemoguce procitati datoteku
    {
        printf("\n\tGreska pri otvaranju fajla \"%s\". (fajl = NULL)\n", imeFajla);
        exit(1); //error poruka je proverena (samo jednom) i radi
    }
    tezina++; //povecanje tezine nakon citanja fajla

    //nasumicno generisanje 5 indeksa od 0 do 11, da bi igra svaki put uzela druga pitanja
    short randomIndexes[5];
    short repeat = 0;

    for (int i = 0; i < 5; i++)
    {
        do //ova do-while petlja sprecava ponavljanje istih indexa tako sto proverava ostatak niza za duplikate i ponavlja generisanje dok god nisu svi unikati
        {
            repeat = 0; //flag koji se setuje na 1 samo ukoliko u proverenom nizu postoji duplikat indeksa, i time forsira ponavljanje petlje
            randomIndexes[i] = rand() % brojPitanja;

            for (int j = 0; j < i; j++)
            {
                if (randomIndexes[i] == randomIndexes[j])
                    repeat = 1;
            }
        } while (repeat == 1);
    }

    //sortiranje indeksa u rastucem poredku da bismo mogli samo jednom da prodjemo kroz datoteku pri upisivanju iz fajla
    for (int i = 0; i < 4; i++)
    {
        for (int j = i + 1; j < 5; j++)
        {
            if (randomIndexes[i] > randomIndexes[j])
            {
                short tmp = randomIndexes[i];
                randomIndexes[i] = randomIndexes[j];
                randomIndexes[j] = tmp;
            }
        }
    }
    //ucitavanje pitanja iz datoteke u strukturu pitanja
    short indexPitanja = 0;
    for (int i = 0; i < brojPitanja; i++)
    {
        //pomocne memorije pri upisu pitanja u strukturu
        char pitanje[PIT_SIZE];
        fgets(pitanje, PIT_SIZE, fajl);

        char odgA[ODG_SIZE];
        fgets(odgA, ODG_SIZE, fajl);

        char odgB[ODG_SIZE];
        fgets(odgB, ODG_SIZE, fajl);

        char odgC[ODG_SIZE];
        fgets(odgC, ODG_SIZE, fajl);

        char odgD[ODG_SIZE];
        fgets(odgD, ODG_SIZE, fajl);

        char odgT;
        fscanf(fajl, "%c ", &odgT);
        //proverava da li je trenutno ucitano pitanje jedno od nasumicno izabranih
        if (i == randomIndexes[indexPitanja])
        { //kopiranje podataka/pitanja sa pomocnih memorija u strukturu sa pitanjima usled ispunjavanja uslova da se trenutno citano pitanje iz datoteke poklapa sa nasumicno izabranim pitanjem
            strcpy(pitanja[indexPitanja].pitanje, pitanje);
            strcpy(pitanja[indexPitanja].a, odgA);
            strcpy(pitanja[indexPitanja].b, odgB);
            strcpy(pitanja[indexPitanja].c, odgC);
            strcpy(pitanja[indexPitanja].d, odgD);
            pitanja[indexPitanja].o = odgT;
            indexPitanja++;
        }
    }
    fclose(fajl); //zatvaranje datoteke
}

void igra()
{
    //unos imena igraca
    int tacni = 0; //brojac tacnih odgovora
    char ime[33];  //string u kome se pamti ime
    //obe vrednosti se kasnije prosledjuju funkciji upisIstorija radi upisivanja novog pokusaja u istorijat
    system(linuxOS ? "clear" : "cls");
    printMilioner(0);
    printf("\n\n\tUnesite ime igraca:\t");
    fflush(stdin);
    fgets(ime, 33, stdin);

    while ((strlen(ime) > 33) || ime[0] == 0 || ime[0] == ' ') //petlja koja proverava da li je ime prekoracilo dozvoljenu velicinu i trazi novi unos dok god velicina ne odgovara uslovu
    {
        system(linuxOS ? "clear" : "cls");
        printMilioner(0);
        printf("\n\n\tUnesite ime igraca (najvise 32 karaktera!!!!!!):\t");
        fflush(stdin);
        fgets(ime, 33, stdin);
    }
    if (linuxOS)
    {
        char c;
        scanf("%c", &c);
    }
    printf("\n\nSrecno, %s!!! (Pritisnite 'Enter' kada ste spremni.)", ime);
    fflush(stdin);
    getchar();

    //pocetak for petlje odnosno igre
    system(linuxOS ? "clear" : "cls");
    for (int i = 0; i < 3; i++) // prva for petlja koja menja kategorije u svakoj iteraciji (svaka 5 pitanja), uzima ta 5 pitanja iz datoteke, i na kraju proverava uslov za kraj igre
    {

        uzimanje();
        char odgovor;     // odgovor na poslednje pitanje
        int indexPitanja; // index pitanja u datoteci na koje je dat poslednji odgovor

        for (int j = 0; j < 5; j++) // druga for petlja koja prolazi kroz 5 ucitana pitanja i stampa ih
        {
            stampanjePitanja(i, j, &odgovor);

            while (odgovor == 'P') // ova while petlja omogucava povratak u pitanje ukoliko igrac odustane od pomoci
            {
                pomoc(i, j, &odgovor);

                if (odgovor == 'P')
                {
                    stampanjePitanja(i, j, &odgovor);
                }
            }

            if (odgovor != pitanja[j].o) //uslov za pogresan odgovor
            {
                indexPitanja = j; //pamcenje indexa for petlje (pitanja) u promenljivu deklarisanu u funkciji
                break;
            }
            else
            {
                indexPitanja = j; //uslov za tacan odgovor
                if (linuxOS)      // !!!!! Ova linija koda se nalazi na svakom mestu na kome se zahteva pritiskanje enter tastera za nastavak, u linux-u getchar() radi drugacije, te je ovo resenje bilo nephodno za isti prikaz kao na windowsu
                {
                    char c;
                    scanf("%c", &c);
                }
                printf("\nCestitamo! Vas odgovor je tacan! (Pritisnite enter za nastavak)\t");
                getchar();
                tacni++;
                continue;
            }
        }

        if (odgovor != pitanja[indexPitanja].o)
        {
            system(linuxOS ? "clear" : "cls");
            printMilioner(0);
            if (linuxOS)
            {
                char c;
                scanf("%c", &c);
            }
            printf("\nNazalost, Vas odgovor je pogresan. Vise srece drugi put!!\n\n\tBroj tacno odgovorenih pitanja: %i\n\n\n\nPritisnite enter za povratak u glavni meni.\t", tacni);
            getchar();
            fflush(stdin);
            break;
        }
        else if ((indexPitanja == 4) && (i == 2)) //igra bi radila i bez ovog if-a jer je to svakako poslednja iteracija obe petlje, ali je svakako dodato radi sigurnosti
        {
            //na sva 15 pitanja je odgovoreno tacno
            system(linuxOS ? "clear" : "cls");
            printMilioner(0);
            printf("\n\tCestitamo! Postali ste milioner!! Svaka cast!!!\n\n");
            printMilioner(0);
            printf("\n\n\nPritisnite enter za povratak u glavni meni.");
            getchar();
            fflush(stdin);
            continue;
        }
    }
    upisIstorija(tacni, ime); // na kraju igre se vrsi obrada istorijata, dodaje se poslednji pokusaj na vrh liste
}

void stampanjePitanja(int i, int j, char *odgovor)
{
    system(linuxOS ? "clear" : "cls");
    printMilioner(0);
    printf("Pitanje %i:\n", ((i * 5) + j + 1)); //stampanje pitanja koristeci prosledjene indekse iz igre
    printf("\t%s", pitanja[j].pitanje);
    printf("\t%s", pitanja[j].a);
    printf("\t%s", pitanja[j].b);
    printf("\t%s", pitanja[j].c);
    printf("\t%s\n\n", pitanja[j].d);

    if (!_5050 && !_pPublike && !_pPrijatelja) //provera flag-ova pomoci (da li su svi 0, odnosno iskorisceni)
    {
        printf("Vas odgovor (A/B/C/D): "); //ukoliko su sve pomoci iskoriscene, nema potrebe nuditi tu opciju igracu
    }
    else
    {
        printf("Vas odgovor (A/B/C/D/P - pomoc): ");
    }
    fflush(stdin);
    scanf(" %c", odgovor);
    fflush(stdin);
    //ova while petlja ce reagovati samo ukoliko uneti odgovor nije jedan od ponudjenih, ili JESTE 'P' ali su sve pomoci iskoriscene
    while ((*odgovor != 'A') && (*odgovor != 'B') && (*odgovor != 'C') && (*odgovor != 'D') && ((*odgovor != 'P') || (*odgovor == 'P' && !_5050 && !_pPublike && !_pPrijatelja)))
    {

        if (!_5050 && !_pPublike && !_pPrijatelja)
        {
            printf("\nNemate vise prava na pomoc. Morate odgovoriti sami na ovo pitanje.\nVas odgovor: "); //ako je uneto 'P' sa iskoricenim pomocima
        }
        else
        {
            printf("\nIzabrana opcija ne postoji. Pokusajte ponovo: "); //ukoliko je unet ilegalan karakter
        }
        fflush(stdin);
        scanf("%c", odgovor);
        fflush(stdin);
    }
}

void pomoc(int i, int j, char *odgovor) //iako ova funkcija ne koristi prosledjene argumente, neophodni su kako bi bili prosledjeni narednoj funkciji kojoj ce biti neophodni
{
    printf("\nUnesite koju pomoc zelite da iskoristite:\n\n"); //svaki naredni if proverava da li je pomoc iskoriscena, jer nema razloga da nudi opciju ako ne postoji
    if (_5050)
        printf("1. 50/50");
    if (_pPrijatelja)
        printf("\t2. Pomoc prijatelja");
    if (_pPublike)
        printf("\t3. Pomoc publike");
    printf("\t0. Nazad\n");

    int izbor;
    scanf("%i", &izbor);
    fflush(stdin);
    while (1)
    {
        if (izbor <= 3 && izbor >= 0)
        { //svaki od ovih if-ova radi samo ukoliko pomoc nije iskoriscena, ukoliko je iskoriscenja uslov iz if-a je jednak 0 (sprecava break-ovanje petlje sa ilegalnim izborom)
            if (izbor == 0)
                break;
            if (izbor == 1 && _5050)
                break;
            if (izbor == 2 && _pPrijatelja)
                break;
            if (izbor == 3 && _pPublike)
                break;
        }
        printf("\nIzabrana opcija ne postoji. Pokusajte ponovo: ");
        scanf("%i", &izbor);
        fflush(stdin);
    }

    switch (izbor) //u odnosu na izbor program prosledjuje argumente izabranoj funkciji
    {
    case 1:
        pomoc5050(i, j, odgovor);
        break;
    case 2:
        pomocPrijatelja(i, j, odgovor);
        break;
    case 3:
        pomocPublike(i, j, odgovor);
        break;
    default:
        *odgovor = 'P'; // prilikom izbora za vracanje iz pomoci (igrac ne zeli pomoc/predomislio se) dodeljuje se vrednost 'P', kako bi while petlja u igri omogucila ponovni odabir pomoci (ako se ponovo predomisli)
    }
}

void pomoc5050(int i, int j, char *odgovor)
{
    int randomNetacan = rand() % 3; //dodeljuje se nasumican broj od 0 do 2

    char nasumicanOdgovor;
    switch (randomNetacan) //bira se odgovor u odnosu na nasumicno izabran broj
    {
    case 0:
        nasumicanOdgovor = 'A';
        break;
    case 1:
        nasumicanOdgovor = 'B';
        break;
    case 2:
        nasumicanOdgovor = 'C';
        break;
    }

    if (nasumicanOdgovor == pitanja[j].o) //ukoliko je nasumicno izabran odgovor isti kao i tacan odgovor, nasumicna vrednost se povecava za 1
        nasumicanOdgovor++;
    //od 4 pitanja, jedno ce sigurno biti izabrrano nasumicno, i jedno ce sigurno biti tacno, sto ostavlja 2 koja se moraju obrisati... naredni if-ovi rade bas to
    if (nasumicanOdgovor != 'A' && pitanja[j].o != 'A')
        strcpy(pitanja[j].a, "\n");
    if (nasumicanOdgovor != 'B' && pitanja[j].o != 'B')
        strcpy(pitanja[j].b, "\n");
    if (nasumicanOdgovor != 'C' && pitanja[j].o != 'C')
        strcpy(pitanja[j].c, "\n");
    if (nasumicanOdgovor != 'D' && pitanja[j].o != 'D')
        strcpy(pitanja[j].d, "\n");

    system(linuxOS ? "clear" : "cls");
    printMilioner(0);
    printf("Pitanje %i:\n", ((i * 5) + j + 1));
    printf("\t%s", pitanja[j].pitanje);
    printf("\t%s", pitanja[j].a);
    printf("\t%s", pitanja[j].b);
    printf("\t%s", pitanja[j].c);
    printf("\t%s\n\n", pitanja[j].d);
    //ovi if-ovi redjaju ponudjene odabire po abecedi, tako da ce ponudjeni odgovori uvek biti  (A/D) a nikad  (D/A) --na primer
    if (nasumicanOdgovor < pitanja[j].o)
        printf("Vas odgovor (%c/%c): ", nasumicanOdgovor, pitanja[j].o);
    else
        printf("Vas odgovor (%c/%c): ", pitanja[j].o, nasumicanOdgovor);
    scanf(" %c", odgovor);
    fflush(stdin);

    while ((*odgovor != nasumicanOdgovor) && (*odgovor != pitanja[j].o)) //petlja proverava da li je validan unos
    {
        if (*odgovor == 'P') //ukoliko je uneto slovo P, igrac je obavesten da ne moze ponovo da koristi pomoc
        {
            printf("\nNemate vise prava na pomoc jer ste vec iskoristili pomoc na ovo pitanje. Vas odgovor: ");
        }
        else
        {
            printf("\nIzabrana opcija ne postoji. Pokusajte ponovo: ");
        }
        scanf(" %c", odgovor);
        fflush(stdin);
    }

    _5050 = 0; //pomoc je iskoriscena i ne moze se ponovo koristiti u ovoj igri
}

void pomocPrijatelja(int i, int j, char *odgovor)
{
    int sanse[4] = {75, 85, 95, 100};  //4 fiksno dodeljene sanse za tacan odgovor
    int randomSansa = rand() % 4;      //nasumican broj od 0 do 3 - sluzi kao index za nasumicno biranje jedne od 4 fiksnih sansi
    int randomBroj = rand() % 100 + 1; //nasumican broj od 0 do 100

    char babinOdgovor;

    if (randomBroj < sanse[randomSansa]) //ukoliko je nasumicno generisan broj od 0-100 manji od minimalne sanse koja je nasumicno izabrana, baba ce dati tacan odgovor
        babinOdgovor = pitanja[j].o;
    else
    {                            //ukoliko je nasumicno generisan broj veci od fiksno zadate vrednosti koja je slucajno izabrana
        randomBroj = rand() % 3; //uzima se novi nasumican broj od 0-2 (ova memorijska lokacija vise nije potrebna pa se koristi ponovo)

        switch (randomBroj) //nasumicno se bira jedan od netacnih odgovora koja je baba dati, tako da ako se iskoristi baba 2 puta za isto pitanje, nece uvek dati isti odgovor (ako pogresi naravno)
        {
        case 0:
            babinOdgovor = 'A';
            break;
        case 1:
            babinOdgovor = 'B';
            break;
        case 2:
            babinOdgovor = 'C';
            break;
        }

        if (babinOdgovor == pitanja[j].o) //i dalje postoji mogucnost da je jedan od karaktera tacan odgovor - ovde se to proverava i ukoliko je tacno, njen odgovor se povecava za 1 (sledeci karakter - ASCII) i zbog toga ni jedan od nasumicnih odgovora nikad nece biti 'D' (to je zadnja opcija u kvizu)
            babinOdgovor++;
    }

    system(linuxOS ? "clear" : "cls");
    printMilioner(0);

    struct timespec tim; //koriscenje sleep komande radi lepseg izgleda programa
    tim.tv_sec = 1;
    tim.tv_nsec = 0;

    printf("\tJa: Halo bako!? Sta mislis? Koji je odgovor na ovo pitanje?\n");
    nanosleep(&tim, 0);
    printf("\tBaba: ALO!?\n");
    nanosleep(&tim, 0);
    printf("\tJa: KOJI JE ODGOVOR NA OVO PITANJE!?\n");
    nanosleep(&tim, 0);
    printf("\tBaba: MISLIM DA JE POD %c!\n", babinOdgovor);
    nanosleep(&tim, 0);
    printf("\tJa: KOLIKO SI SIGURNA, BABA!?\n");
    nanosleep(&tim, 0);
    printf("\tBaba: %i POSTO!\n", sanse[randomSansa]); //ovde se prikazuje procenat izabrane sanse igracu, tako da sam odluci da li vredi slusati babu ili ne
    nanosleep(&tim, 0);
    printf("\tJa: HVALA PUNO, BABA!\n");
    nanosleep(&tim, 0);

    _pPrijatelja = 0; //setovanje flag-a - iskorriscena pomoc
    if (linuxOS)
    {
        char c;
        scanf("%c", &c);
    }
    printf("\n\nPritisnite Enter da nastavite.");
    getchar();

    printPitanjeNakonPomoci(i, j, odgovor); //prosledjivanje indeksa pitanja i odgovora posebnoj funkciji za stampanje
}

void pomocPublike(int i, int j, char *odgovor)
{
    system(linuxOS ? "clear" : "cls");
    printMilioner(0);
    printf("\nSto ljudi se nalazi u publici. Svako od njih ima 50%% sanse da pogodi tacan odgovor.\n");

    int netacni[3] = {0, 0, 0}; //niz koji broji netacne odgovore za 3 pitanja
    int brojacTacnihGlasova = 0;

    for (int k = 0; k < 100; k++) //nasumicno biranje 100 odgovora
    {
        if ((rand() % 100 + 1) < 50) //ako je broj manji od 50, to je tacan glas
            brojacTacnihGlasova++;
        else
        {
            netacni[rand() % 3]++; //u suprotnom, dodeljuje se glas u niz na nasomicno izabran index
        }
    }

    int index = 0;
    char odgovoriSlova[4] = {'A', 'B', 'C', 'D'};

    for (int k = 0; k < 4; k++) //crtanje grafika sa odgovorima
    {
        printf("\n%c | ", odgovoriSlova[k]); //automatsko stampanje slova odgovora

        if (pitanja[j].o == odgovoriSlova[k]) //ako je trenutno slovo tacan odgovor pokrenuce se petlja za crtanje tacnih glasova
        {

            for (int z = 0; z < brojacTacnihGlasova; z++)
                if (linuxOS == 1)
                    printf("\u2593");
                else
                    printf("%c", pu);
        }
        else //ukoliko slovo nije tacan odgovor, stampace se broj glasova za to izabrano slovo

            for (int z = 0; z < netacni[index]; z++)
                if (linuxOS == 1)
                    printf("\u2593");
                else
                    printf("%c", pu);
        index++; //menjanje slova
    }

    if (linuxOS)
    {
        char c;
        scanf("%c", &c);
    }
    printf("\n\nPritisnite Enter da bi se vratili na pitanje.");
    getchar();

    _pPublike = 0; //setovanje flag-a - pomoc je iskoriscena

    printPitanjeNakonPomoci(i, j, odgovor); //prosledjivanje indeksa pitanja i odgovora posebnoj funkciji za stampanje
}

void printPitanjeNakonPomoci(int i, int j, char *odgovor) //posebna funkcija za stampanje
{                                                         //ova funkcija je ista kao i stampanjePitanja, jedina razlika je sto ova funkcija ne dozvoljava da se koristi Pomoc ponovo (do ove funkcije se u kodu moze doci samo koriscenjem pomoci svakako)
    system(linuxOS ? "clear" : "cls");
    printMilioner(0);
    printf("Pitanje %i:\n", ((i * 5) + j + 1));
    printf("\t%s", pitanja[j].pitanje);
    printf("\t%s", pitanja[j].a);
    printf("\t%s", pitanja[j].b);
    printf("\t%s", pitanja[j].c);
    printf("\t%s\n\n", pitanja[j].d);

    printf("Vas odgovor (A/B/C/D): ");
    scanf(" %c", odgovor);
    fflush(stdin);

    while ((*odgovor != 'A') && (*odgovor != 'B') && (*odgovor != 'C') && (*odgovor != 'D'))
    {
        if (*odgovor == 'P')
        {
            printf("\nNemate vise prava na pomoc jer ste vec iskoristili pomoc na ovo pitanje. Vas odgovor: ");
        }
        else
        {
            printf("\nIzabrana opcija ne postoji. Pokusajte ponovo: ");
        }
        scanf(" %c", odgovor); //pamti odgovor i prosledjuje ga skroz nazad do funkcije igra, gde se igra nastavlja
        fflush(stdin);
    }
}
/* ==========         END  --  FUNKCIJE-Elaborate       ========== */