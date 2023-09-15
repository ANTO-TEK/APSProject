# APSProject

Mister Joker, proprietario di un Sala Bingo decide di creare delle stanze virtuali online in cui le persone possono incontrarsi per partecipare a vari giochi di fortuna, ossia giochi dove sulla base di valori casuali c'è un vincitore (es., tombola, roulette). Mister Joker vuole spendere poco e quindi contatta un gruppo di studenti del corso di laurea magistrale in ingegneria informatica dell'università di Salerno chiedendogli di realizzare una funzionalità cruciale di tale software: "la generazione continua nel tempo di stringhe casuali"; tali stringhe devono essere quindi non controllate/decise/calcolate da nessuno (individualmente) dei partecipanti in una sala virtuale, ma comunque stabilita attraverso la partecipazione di tutti i partecipanti (e solo loro, ed il server visto che in molti giochi c'è la presenza attiva del Banco). Mister Joker vorrebbe una soluzione con massima trasparenza, altrimenti da casa tutti penserebbero ad imbrogli.\\

Chi è al potere ha da poco imposto il divieto di partecipare ad eventi sociali anche on-line a chi non possiede il Green Pass; quindi, chi lo possiede deve esibirlo per partecipare agli eventi sociali, e le stanze virtuali di una Sala Bingo sono considerate come appartenenti a tali categorie. Si è messo tra i piedi il garante per la protezione dei dati personali che ha imposto il divieto di invio su canali telematici del Green Pass in quanto esso mostra dati personali in eccesso rispetto a quanto strettamente necessario per l'accesso ai servizi. Il governo, quindi, ha deciso di pubblicare una call aperta a tutti per proposte di formato del Green Pass 2.0. Tale formato dovrà ancora prevedere la solita sequenza di informazioni del soggetto (cioè i dati già presenti nel tradizionale Green Pass) associate ad un'unica firma digitale rilasciata dall'autorità sanitaria. Tuttavia, oltre ad essere esibito di persona mostrando il QR-Code stampato, si richiede che chi lo possiede su smartphone/computer possa esibire telematicamente solo le informazioni strettamente necessarie sulla base del contesto (es., mostrare il tipo di vaccino, le date, o l'essere stati positivi al virus, insomma quello che serve anziché mostrare tutto), cioè, esibendo lo stretto necessario o per accedere ad un servizio. Gli studenti del corso di laurea magistrale in ingegneria informatica dell'università di Salerno, in cerca di pecunia sono intenzionati a partecipare alla competizione del Green Pass 2.0. Mister Joker vuole giocare d'anticipo e richiede quindi agli studenti di realizzare questa funzionalità per l'accesso alle sale virtuali della sua Sala Bingo, anche se ancora non sa quali specifiche informazioni tra quelle presenti nel Green Pass 2.0 dovranno essere esibite per accedere alla sala virtuale sotto la benedizione del DPA (cioè Data Protection Authority, cioè il garante). Tuttavia, questo non sarà un problema, perché gli studenti intendono progettare un sistema dinamico tale da permettere al proprietario del GP 2.0 di usarlo in sicurezza anche al variare delle politiche nel tempo circa quali dati bisogna possedere nel GP 2.0 per accedere ad un servizio. Inoltre, Mister Joker vuole che questo sistema sia anche utile per identificare le persone presenti nella sala virtuale, in modo che possano accedere al proprio conto virtuale da utilizzare per le vincite/perdite nei vari giochi. Gli studenti, quindi, progetteranno un GP 2.0 che 1) viene emesso dalla stessa autorità fidata "Ministero della Salute" che emetteva il GP 1.0; tale autorità è fidata nello stabilire i dati anagrafici e sanitari similmente ad una certification authority che attesta i dati inseriti in un ceritficato digitale, per cui è coinvolgibile solo in fase di generazione di GP 2.0 (ed eventuali revoche), ma nulla di più; 2) permette ad un utente di identificarsi con la sala Bingo per accedere al proprio profilo, 3) permette successivamente ad un utente che ha un GP 2.0 che contiene informazioni che soddisfano la politica imposta dal garante, di accedere alla funzionalità di generazione continua di stringhe casuali.\\

Chiarimento: "per generazione continua" si intende che ogni volta che serve una stringa casuale le parti interessate a tale stringa (sarebbero i giocatori coinvolti nella partita) partecipano a generarne una. Ovviamente non può un'unica partecipazione essere tale da produrre tutte le stringhe che saranno usate in futuro senza ulteriori interazioni, in quanto ad esempio questo permetterebbe nei giochi di sapere quali saranno i prossimi numeri estratti o carte prese dal mazzo.
Nota: alcuni requisiti possono essere tra loro contrastanti e non è affatto chiaro che tutte le proprietà desiderate possano essere raggiunte in pieno. E’ verosimile che tali sistemi si reggano su compromessi/assunzioni e vari meccanismi che provano a mitigare criticità sapendo che i rischi non sono evitabili in assoluto.\\

Ci sono anche gli oppositori dell'innovazione, ossia dinosauri che anziché studiare le nuove tecnologie non fanno altro che indicarne genericamente i rischi con il solo scopo di lasciare tutto così com’è, riferendosi a chi le studia col termine "tecnocrati". Sono in genere allarmisti che puntano sul fatto che tutti i dispositivi possono essere compromessi, la sicurezza assoluta non esiste, chi propone innovazione è di solito una volpe che vuole approfittarsi dell'ignoranza altrui. Sono i no-fox. Per evitare facili strumentalizzazioni da parte di tali complottisti è quindi necessario che un sistema sia trasparente nel senso che non debba affidarsi eccessivamente ad una presunta parte fidata, ma abbia invece una progettazione ed analisi che permetta a tutti di verificarne la bontà limitando il danno che può essere causato da un qualunque avversario. Si tratta di una richiesta esplicita di Mister Joker che ha ricordato anche che la musica in background delle sue sale virtuali sarà di Franco Califano che diceva in una sua opera: "Non mi fido di nessuno".
