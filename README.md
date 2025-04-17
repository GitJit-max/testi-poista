<!-- Start of auto generated content -->

> [!TIP]
> The table of contents can be accessed by pressing the unordered list icon ![octicon](../asset/octicon-list-unordered.svg) on top the right corner.

<p align="center">
  <a href="01-intro.md">&lt;&lt; Previous Chapter: 1 - Introduction</a>
     |
  <a href="03-basic-terminal.md">Next&nbsp;Chapter:&nbsp;3&nbsp;&#8209;&nbsp;Basic&nbsp;terminal&nbsp;usage&nbsp;&gt;&gt;</a>
</p>

<!-- End of auto generated content -->

# Luku 2 - Unix järjestelmän perusteet

Linuxia on pidetty aloittelijoille vaikeana järjestelmänä. Perusteiden opettelu saattaa tuntua turhauttavalta, koska järjestelmä on suunniteltu eri lähtökohdista kuin useimmille tuttu Windows (tai sen edeltäjä MS-DOS). Moni asia käsitellään hyvin eri tavalla. Muista kuitenkin, että kukaan ei opi käyttämään tietokonetta tehokkaasti viikossa tai kahdessa, ei edes Windowsissa. [^linufi] Jotta voi käyttää linuxia tehokkaasti, on hyvä oppia järjestelmän perusteet sekä jotain sen historiasta.

[^linufi]: [Linux.fi ohjesivusto - Aloittelijalle, accessed 2021](https://www.linux.fi/wiki/Aloittelijalle)

<a id="introduction-to-the-text-interface"></a>

## 2.1 Johdatus komentokieli-käyttöliittymään

**Liittymä** (englanniksi **interface**) viittaa tapoihin, joilla ohjelmat kommunikoivat muiden ohjelmien sekä ihmiskäyttäjien kanssa. Suuri osa unix-yhteisön perinteistä, ohjelmien liittymien suunnittelussa, saattaa tuntua oudoilta ja vanhanaikaisilta. Perinteellä on kuitenkin sisäinen logiikka, joka kannattaa oppia ja ymmärtää. Se heijastaa pitkän historian aikana kertynyttä heuristiikkaa valmiiden, etukäteen mietittyjen tai hankittujen ratkaisumallien soveltamisesta ongelmanratkaisussa. Samat mekanismit mahdollistavat kommunikaation tehokkaasti sekä muiden ohjelmien että ihmisten kanssa. [^raymond]

<a id="retained-utility"></a>

### Komentokieli on säilyttänyt hyödyllisyytensä [^raymond] <!--update internal links if changed-->

Graafisten käyttöliittymien puute katsotaan nyky käyttöjärjestelmien aikakaudella ongelmaksi (englanniksi GUI eli Graphical User Interface). Unix oppi on päinvastainen: Heikot tekstipohjaiset eli komentokieliset käyttöliittymät ovat vähemmän ilmeinen, mutta yhtä vakava puute (englanniksi CLI eli Command Language Interface).

#### Heikon tekstikäyttöliittymän seuraukset

Jos järjestelmän ja sovellusohjelmien tekstikäyttöliittymä on heikko tai sitä ei ole lainkaan, on siitä seuraavanlaiset seuraukset:
- Järjestelmän etähallinta on harvoin tuettua, sitä on vaikeampi käyttää ja se on verkkointensiivisempää.
- Taustaprosesseja (kuten daemonit ja serverit) on todennäköisesti vaikea ohjelmoida millään armollisella tavalla.
- Varsinkin yksinkertaiset ohjelmat, joissa ei ole vuorovaikutteisuutta, paisuvat tarpeettomasti graafisen käyttöliittymän myötä. GUI:n luominen lisää huomattavasti kehitysaikaa ja monimutkaisuutta projektiin, sekä kuluttaa enemmän järjestelmäresursseja.
- Ohjelmia ei suunnitella toimimaan yhteistyössä keskenään uusilla, luovilla ja odottamattomilla tavoilla (katso huomautus alla). Ei synny tulosteita (englanniksi output), joita voisi käyttää syötteinä (englanniksi input).

> [!NOTE]
> Unix ohjelmistokehitysperinteessä on aina pyritty tietoisesti olemaan rajaamatta ohjelmien kohderyhmää ja käyttömahdollisuuksia. Tällaisessa ohjelmistokehityksessä mahdollistetaan jokaisen ohjelman tulosteesta (englanniksi output) tulevan toisen, vielä toistaiseksi tuntemattoman ohjelman syöte (englanniksi input). Ohjelmoijat eivät koskaan olettaneet tietävänsä kaikkia mahdollisia käyttötarkoituksia, joihin heidän ohjelmiaan voitaisiin käyttää.

#### Kuormittava muistinvaraisesti

Komentokielisen käyttöliittymän haittapuolena on tietysti se, että se on melkein aina hyvin kuormittava muistinvaraisesti, eikä mahdollista käyttöä intuition varassa, ilman aiempaa tietoa ja ohjeisiin perehtymistä. Useimmat epätekniset loppukäyttäjät pitävät tällaista käyttöliittymää kryptisenä ja suhteettoman vaikeasti opittavana.

#### Vastustus vähenee taitojen kehittyessä

Vastustus komentokielistä käyttöliittymää kohtaan yleensä vähenee käyttäjän tieto-taitojen kehittyessä. Erityisesti aktiivi käyttäjät saavuttavat, monilla osa-alueilla, pisteen, jossa komentokielen tiiviydestä ja ilmaisuvoimasta tulee arvokkaampaa kuin muistikuorman välttäminen.

Aloittelijat pitävät enemmän graafisen käyttöliittymän työpöydän helppoudesta, mutta kokeneet käyttäjät huomaavat usein vähitellen, että komentojen kirjoittaminen komentotulkkiin on hyödyllisempää. Varsinkin kun ongelmat laajenevat ja niihin liittyy enemmän valmiiksi kirjoitettuja, toistuvia toimintoja ja aliproseduureihin jäsennystä.

> Esimerkiksi *mitä näet sitä saat* WYSIWYG -työpöytäjulkaisuohjelma (englanniksi What You See Is What You Get) kuten Microsoft Word tai Libre Office Writer on yleensä helpoin tapa laatia suhteellisen pieniä ja jäsentymättömiä asiakirjoja, kuten liikekirjeitä. Mutta monimutkaisemmissa kookkaammissa kirjojen julkaisutöissä, jotka kootaan osioista ja jotka saattavat vaatia formaattimuutoksia ja rakenteellista manipulointia kokoamisen aikana, on yleensä tehokkkaampi valinta merkintäkielen (kuten markdown) tai metakielen (kuten XML) kombinaatio tekstin ladontajärjestelmään (kuten LaTex).

#### Skriptattavuus

Varhaisen Unixin komentokieli on säilyttänyt hyödyllisyytensä näihin päiviin asti erityisesti siksi, että komentokieli käyttöliittymät tukevat ohjelmien skriptattavuutta ja yhdistämistä. Rajapinnan **skriptattavuus** mahdollistaa ohjelmien käytön komponentteina muissa ohjelmissa ja kokonaisuuksissa. Tämän vähentää kalliin mukautetun koodauksen tarvetta ja tekee toistuvien tehtävien automatisoinnista suhteellisen helppoa. Tätä valtavaa tuottavuuden lisäystä, ei ole saatavilla useimmissa muissa ohjelmistoympäristöissä.

Graafiset työpöytäkäyttöliittymät eivät yksinkertaisesti ole lainkaan skriptattavissa. Jokaisen vuorovaikutuksen niiden kanssa on oltava ihmislähtöistä. Käyttäjä on pelkistetty liukuhihnatyöläiseksi, jonka on suoritettava sama tehtävä yhä uudelleen ja uudelleen. Eikä ihminen suoriudu moisesta virheittä.

Graafisten työpöytäkäyttöliittymien kanssa (skriptausta vastaava) ohjelmien tietojen yhdistäminen, rutiiniprosessien tehostus ja ihmisvirheen minimointi vaatii ohjelmistorobotiikkaa. **Ohjelmistorobotti** käyttää sovellusohjelmia samoin kuin ihminen tekisi. Siksi ohjelmistorobottien määrittelyä ei yleensä kutsuta ohjelmoinniksi, vaan virtuaalisen työntekijän kouluttamiseksi.

<!-- Yleensä (vaikkakaan ei aina) komentokieli käyttöliittymät ovat etulyöntiasemassa myös **tarkkuuden** suhteen.
- Ajatellaanpa vaikka graafisen kuvan väritaulukon muuttamista. Jos haluat muuttaa yhtä väriä (vaikkapa vaalentaa sitä määrällä, jonka tiedät oikeaksi vasta, kun näet sen), visuaalinen vuoropuhelu väripoimintawidgetin kanssa on lähes pakollista.
- Oletetaan kuitenkin, että sinun on korvattava koko taulukko määrätyillä RGB-arvoilla tai luotava ja indeksoitava suuri määrä pikkukuvia. Nämä ovat operaatioita, joiden määrittelyyn graafisilla käyttöliittymillä ei yleensä ole ilmaisuvoimaa. Jopa silloin, kun ne pystyvät, oikein suunnitellun komentokielisen suodatinohjelman käyttäminen tekee työn paljon ytimekkäämmin. Jopa nykyaikaisissa järjestelmissä graafiset ohjelmat kutsuvat todennäköisesti (~40 vuotta vanhoja) yksinkertaisia CLI-apuohjelmia taustalla (jotka tekevät suuren osan raskaista töistä). -->

<a id="command-language-interface"></a>

### I - Komentoliittymä

**Komentoliittymä** eli komentokielikäyttöliittymä (englanniksi **Command Language Interface**) on tapa järjestää tietokoneohjelmien käyttö ja kommunikointi tekstimuotoisena. Sama liittymä mahdollistaa kommunikoinnin sekä ihmisen kanssa, ehkä keskenään eri ohjelmien välillä (katso [Kappale: Komentokieli](#ii---komentokieli)).

<!-- > Komentokielistä käyttöliittymää, pidetään vaikeammin opittavina kuin graafista käyttöliittymää. Komentopohjaiset järjestelmät ovat kuitenkin ohjelmoitavissa. Tämä antaa niille joustavuutta, jota ei ole saatavilla grafiikkapohjaisissa järjestelmissä, sillä niisä ei ole ohjelmointirajapintaa. -->

<a id="command-language"></a>

### II - Komentokieli

**Komentokieli** eli komentosarjakieli (englanniksi **Command Language**) viittaa tietokoneen komentoliittymän kielioppisääntöihin ja on vahvasti kytköksissä taustalla olevaan käyttöjärjestelmään. Komentokielellä on yksinkertaisempi kielioppi kuin yleiskäyttöisellä ohjelmointikielellä. Toinen ero komentokielen ja ohjelmointikielen välillä on se, että komentokieli luetaan, jäsennetään ja suoritetaan järjestyksessä. Syntaksivirhe keskellä komentokielen komentosarjaa havaitaan vasta, kun suoritus saavuttaa sen. Ohjelmointikieli sitä vastoin jäsennetään kokonaan ennen suorituksen aloittamista. Yleisiä esimerkkejä komentokielistä ovat *GNU Bash* ja *Microsoft Batch*. Komentokieli on optimoitu (**interaktiiviseen**) käyttöön komentorivillä, mutta monimutkaisempia ja usein käytettyjä komentosarjoja voidaan tallettaa tiedostoon eräänlaisiksi pienoisohjelmiksi (englanniksi shell scripting).

<a id="command-language-interpreter"></a>

### III - Komentotulkki [^hoffman]

[^hoffman]: [Chris Hoffman - What's the difference between Bash and other shells?](https://www.howtogeek.com/68563/htg-explains-what-are-the-differences-between-linux-shells/#:~:text=The%20most%20prominent%20progenitor%20of,worked%20at%20AT%26T's%20Bell%20Labs.)

Kun käynnistät terminaali-ikkunan tai kirjaudut muutoin komentoriville, järjestelmä lataa **Shell** ohjelman (kuten BASH), joka on ennenkaikkea käskynkäsittelyohjelma, käskykielen **komentotulkki** (englanniksi **Command Language Interpreter**, **Command Processor**). Se suorittaa komennot, jotka se lukee a) komentorivin merkkijonosta, b) määritetystä tiedostosta tai c) vakiosyötteestä (katso [Kappale: Standardivirrat](06-inter.md#standardivirrat)). d) Myös erilaiset sovellusohjelmat ja järjestelmäpalvelut käyttävät shell ohjelmaa taustalla.

Shell ohjelma toteuttaa *komentokielen rajapinnan*, kun se kommunikoi järjestelmän muiden osien kanssa saamiensa komentojen pohjalta. Shell viittaa usein myös kieleen, jota se tulkkaa. Eli ne ovat myös **tulkattuja kieliä**. Shell ohjelmat ovat monelle myös ensisijainen käyttöliittymä ja ominaisuuksia on kertynyt vuosien saatossa niin paljon, että voitaneen puhua jo jonkinlaisesta **shell-ympäristöstä** tai **komentotulkkiympäristöstä**.

<!-- The analogy is with a nut: outside is the shell, inside is the kernel. -->

#### Vaihtoehtoisia komentotulkkeja [^hoffman]

Ensisijaisen shell-ohjelman tiedostopolku on ` /bin/sh `. Nykyjakeluissa tiedosto osoittautuu käytännössä aina symboliseksi linkiksi johonkin [POSIX-yhteensopivaan](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html) komentotulkkiin, tavallisimmin Bourne Again Shelliin ` /usr/bin/bash `. Halutessaan komentotulkin voi vaihtaa toiseen.

Vaihtoehtoisia shell-ympäristöjä voi asentaa käyttöjärjestelmän paketinhallinnasta ja kokeilla kutsumalla niitä tiedostonimellä kuten ` $ sh↵ `, ` $ dash↵ `, ` $ zsh ↵ ` käynnistääksesi kyseisen ympäristön. Komento ` $ exit↵ ` käskee poistua takaisin alkuperäiseen shell-ympäristöön.

Voit kokeilla komentoa ` $ chsh↵ ` (Change Shell) vaihtaaksesi oletusarvoisen komentotulkin. Eli sen jonka näet sisäänkirjautumisen yhteydessä (englanniksi *login shell*). Katso vinkki alla, jos kamppailet peruuttaaksesi oletusarvoisen login shell -vaihto-operaation.

> [!TIP]
> Ohjelman sulkeminen tai toiminnon pysäyttäminen voi osoittautua ylivoimaiseksi ensikertaa komentokäyttöliittymässä. Uutena käyttäjänä voit kokeilla seuraavia pikanäppäimiä erilaisten komentorivitilanteiden keskeyttämiseksi:
>
> | Pikanäppäin | Toiminto |
> |:--- |:--- |
> | ` Ctrl + D ` | Tekstinsyötön lopettaminen |
> | ` Ctrl + C ` | Keskeytä nykyinen prosessi |
> | ` q ` | Keskeytä ` $ less ` ja ` $ more ` |
> | ` Ctrl + X ` | Sulje ` $ nano ` |
> | ` Ctrl + X, Ctrl + C ` | Sulje ` $ emacs ` |
> | ` Esc, :qa!, Ent ` | Sulje ` $ vi ` |
> | ` Alt + F4 ` | Sulje nykyinen ikkuna |

#### Komentotulkki: Thompson Shell [^hoffman]

Ensimmäinen Unix-shell **Thompson Shell** kehitettiin AT&T:n Bell Labsissa ja julkaistiin vuonna 1971.

> Shell-ohjelmat ovat siitä lähtien rakentuneet saman konseptin varaan, jatkuvin parannuksin, kehittyen varsinaisiksi shell- ja komentotulkkiympäristöiksi. Niihin on lisätty erilaisia uusia ominaisuuksia, toimintoja ja nopeusparannuksia. Esimerkiksi Bash tarjoaa komentojen ja tiedostonimien [automaattisen täydennyksen](03-basic-terminal.md#automaattinen-täydennys), kehittyneitä skriptiominaisuuksia, [komentohistorian](#komentohistoria), [konfiguroitavia värejä](07-advanced-terminal#komentokehotteen-kustomointi), [komentojen aliaksia](03-basic-terminal.md#alias) ja monia muita ominaisuuksia, joita ei ollut saatavilla vuonna 1971, kun ensimmäinen komentotulkki julkaistiin.

#### Komentotulkki: Bourne Shell [^hoffman]
    
Nykyaikaisten shell-ympäristöjen merkittävin kantaisä on **Bourne Shell** (tunnetaan myös nimellä **sh**), joka on nimetty luojansa Stephen Bournen mukaan, joka työskenteli myös AT&T:n Bell Labsissa. Bourne Shell julkaistiin vuonna 1979, jolloin siitä tuli ensisijainen Unix-shell. Bourne Shell tuki muun muassa [komentojen korvaamista](07-advanced-terminal#laajennukset-ja-lainaukset), [putkitusta](06-inter.md#vakiotulosteen-putkitus), muuttujia, ehtojen testausta ja silmukointia. Bourne Shell ei vielä tarjonnut käyttäjille juurikaan muokkausmahdollisuuksia, eikä tukenut nykyaikaisia hienouksia kuten aliakset ja komentojen täydentäminen.

#### Komentotulkki: C Shell [^hoffman]

**C Shell** eli **csh** kehitettiin 1970-luvun lopulla Bill Joyn toimesta Kalifornian yliopistossa Berkleyssä. Se lisäsi paljon vuorovaikutteisia elementtejä, joilla käyttäjät pystyivät hallitsemaan järjestelmiään, kuten aliakset (pikanimet pitkille komennoille), työnhallintaominaisuudet, komentohistoria ja paljon muuta. Ajan mittaan monet ihmiset korjasivat C-komentotulkin virheitä ja lisäsivät siihen ominaisuuksia, mikä huipentui csh:n parannettuun versioon, joka tunnetaan nimellä **tcsh**.

#### Komentotulkki: Korn Shell [^hoffman]

David Korn, Bell Labsista työskenteli **Korn Shell**:n eli **ksh**:n parissa, joka yritti parantaa tilannetta olemalla taaksepäin yhteensopiva Bourne Shell kielen kanssa, mutta lisäämällä monia csh-kuoren ominaisuuksia. Se julkaistiin vuonna 1983, mutta levitystä rajoittavalla omistusoikeudellisella lisenssillä. Siitä tuli vapaa ohjelmisto vasta 2000-luvulla, jolloin se uudelleen julkaistiin avoimen lähdekoodin lisenssillä.

#### Komentotulkki: Bourne Again Shell [^hoffman]

GNU-projekti kehitti komentotulkin, omalla vapaan ja avoimen lähdekoodin lisenssillä (katso [Luku 1, Kappale: GNU General Public -lisenssi](01-intro.md#gnu-general-public--lisenssi)), osaksi vapaata käyttöjärjestelmäänsä ja antoi sille nimen **Bourne Again Shell** eli **bash**. Vuoden 1989 ensijulkaisun jälkeen Bash:ia on paranneltu vuosikymmenien ajan. Ja se on edelleen useimpien GNU/Linux-jakeluiden oletusarvoinen shell-ympäristö.

Bash oli myös macOS:n oletuskomentotulkki vuoteen 2019 asti. Kuitenkin macOS Catalina versiosta lähtien tilalla on ollut **Z Shell** eli **zsh**, jonka MIT-lisenssi sallii vapaammin käytön suljetun lähdekoodin ohjelmistoissa.

> [!NOTE]
> Vaikka valtaosa GNU/Linux-jakeluista on päätyi bashiin, kehittäjät eivät luopuneet uusien shell ympäristöjen luomisesta.

#### Komentotulkki: Almquish Shell [^hoffman]

Kenneth Almquist loi Bourne Shell -kloonin nimeltä **Almquish Shell**, joka tunnetaan myös nimillä **A Shell** ja **ash**. Se on suunniteltu POSIX-yhteensopivaksi ja kevyeksi. Se on nopeampi kuin bash, koska siinä ei ole kaikkia sen ominaisuuksia. Siitä tuli suosittu komentotulkki unixin NetBSD-haarassa. Ash-shell on karsitumpi ja kevyempi kuin bash, minkä vuoksi se on suosittu sulautetuissa unix-järjestelmissä (englanniksi embedded system).

Sittemmin ash on muokattu Debian alustalle, nimellä **dash**. Ubuntu käyttää dash-tulkkia non-interaktiivisissa tehtävissä keveytensä ja vähäisten ohjelmointi-kirjasto-riippuvuuksiensa vuoksi. Tämä nopeuttaa taustalla suoritettavia tehtäviä, sekä käyttöä skriptikielenä. Ubuntu käyttää kuitenkin edelleen bashia vuorovaikutteisiin komentokielikäyttöliittymiin. Joten ihmis käyttäjillä on edelleen käytössään moderni monipuolinen komentokielinen toimintaympäristö.

#### Komentotulkki: Z Shell [^hoffman]
    
Yksi suosituimmista uudemmista shell-ympäristöistä on **Z Shell** eli **zsh**. Paul Falstadin vuonna 1990 aloittama POSIX-yhteensopiva zsh on Bourne-tyylinen, sisältää bashin ominaisuudet, mutta on ennenkaikkea  muokattavissa ja laajennettavissa liitännäisillä (englanniksi plug-ins). Se on tällä hetkellä luultavasti eniten ominaisuuksia sisältävä unix-shell-ympäristö. Käyttäjäyhteisön kerää kolmansien osapuolten lisäosia ja teemoja [Oh My Zsh](https://github.com/ohmyzsh/ohmyzsh/) verkkosivustolle.

#### Komentotulkki: Friendly Interactive Shell [^hoffman]

Toinen uudempi shell-ympäristö on **Friendly Interactive Shell** eli **fish**, jota on julkaistu vuodesta 2005 lähtien. Siinä on ainutlaatuinen komentokielen syntaksi, joka on suunniteltu hieman helpommaksi oppia. Ominaisuuksiin kuuluu myös runsas käytön aikainen ohjeistus. Mutta se, mitä opit käyttämällä fishiä, ei auta sinua Bourne-peräisissä ympäristöissä. Fish ei ole täysin POSIX-yhteensopiva. Kehittäjät ovat päättäneet sivuta standardia niiltä osin, kuin se on ollut heidän mielestänsä tarpeellista. [^fi-fish]

[^fi-fish]: [Linux.fi ohjesivusto - Fish, accessed 2025](https://www.linux.fi/wiki/Fish)

### IV - Komentokehote

Komentokäyttöliittymässä dollarimerkki ja ristikkomerkki ilmaisevat valmiutta vastaanottaa komentoja (**komentokehote**, englanniksi **Command Prompt**).  **Dollarimerkki** (<span>$</span>) viittaa työskentelyyn käyttäjänä tavallisin alhaisin käyttöoikeuksin. **Ristikkomerkki** (#) viittaa työskentelyyn pääkäyttäjän korotetuin oikeuksin. Kehotemerkki on myös itse vaihdettavissa ja jopa kokonaan poistettavissa. Joissakin yhteyksissä saattaa esiintyä muitakin kehotemerkkejä, kuten suurempi kuin (>) merkki ja prosenttimerkki (%).

> Voinemme vain arvailla UNIX dollarikehotteen alkuperää. Vuonna 1979 julkaistussa UNIX versiossa 7 oli ensimmäisenä dollarimerkki. Kyseisessä versiossa otettiin käyttöön Bourne Shell, joka korvasi aiemmissa UNIX-versioissa käytetyn Thompson Shellin. UNIX versiossa 6 ei ollut dollarimerkkiä. (Bourne Shellin kirjoittaja Steve Bourne oli Bell Labsin työntekijä). Kuudennen version aikakautena ja aiemmin, ennen kuin UNIXia myytiin kaupallisesti, sitä jaettiin täydellisen lähdekoodin kanssa. Siirtyminen dollarimerkkiin voidaan ajatella liittyvän UNIXin kaupallistamiseen (<span>$</span>hell).

<!--
> The Unix **Shell Prompt** is the equivalent of the Windows **Command Prompt**
>
> - **Shell** = the outer layer
> - **Prompt** = to encourage somebody to speak
> - **Command** = an order given
-->

### Terminaali emulaattori

**Terminaali-emulaattori** tai *terminaali-sovellus* on tietokoneohjelma, joka matkii perinteistä videopäätettä jossakin muussa näyttöarkkitehtuurissa. Graafisen työpöytäkäyttöliittymän sisällä olevaa terminaali-emulaattoria kutsutaan *terminaali-ikkunaksi*. Virtuaalinen päätelaite tarjoaa käyttäjälle *komentokielisen käyttöliittymän* shell-ympäristössä (katso [Kappale: Komentotulkki](#iii---komentotulkki-hoffman)).

> Ennen kuin Linux-projekti laajeni täydeksi käyttöjärjestelmän ytimeksi, sen kehittäjä Linus Torvalds teki aluksi pelkän terminaali-emulaattorin. Toisin sanoen Linuxia ajettiin aluksi puhtaasti tekstimoodissa, täysin ilman graafista käyttöliittymää.

#### Mac ja Windows käyttäjät ovat unohtaneet komentokäyttöliittymän

Windowsissa komentorivi ei ole enää peruskäytössä, ja mahdollisuus käynnistää tietokone komentorivitilassa on poissa. Linux-jakeluissa komentorivi on edelleen korostetussa osassa, sekä hyvässä että pahassa. Linux-jakeluiden graafiset hallintatyökalut eivät ole korvanneet komentorivin käyttöä, sillä jakeluiden kehittäjien mielestä asiat hoituvat edelleen kätevimmin komentokäyttöliittymässä.

Kun Linux tuli markkinoille vuonna 1991 ihmiset olivat tottuneet työskentelemään vielä pääasiassa komentokäyttöliittymillä. On totta, että Windows ja Macintosh käyttöjärjestelmät olivat olleet käytössä kuutisen vuotta, mutta grafiinen käyttöliittymä oli monen mielestä muistinhimoinen "nice to have". Jos halusi grafiikkaa, piti hankkia kallis tietokone, joka ei ollut monen mielestä kustannusen arvoinen.

Vuosien saatossa ihmiset, jotka käyttivät Macin ja Windowsin kaltaisia työpöytäkäyttöjärjestelmiä, ovat pääosin unohtaneet, että komentokielikäyttöliittymä on yhä olemassa. Mutta varsinkin käyttäjät, jotka haluavat tehdä operaatioita massoittain tai etänä, käyttävät komentokehotetta edelleen. Marraskuussa 2006 Microsoft julkaisi Windows PowerShell -nimisen ohjelman juuri tästä syystä.

<a id="cut-and-paste"></a>

## 2.2 Leikkaa ja liitä

### Poikkevat pikanäppäimet

Terminaali-ikkunassa on poikkevat pikanäppäimet kopioimiseen/liittämiseen:
- **` Ctrl + Shift + V `** = Tekstin liittäminen terminaali-ikkunaan.
- **` Ctrl + Shift + C `** = Tekstin kopiointi terminaali-ikkunasta.
- Tutumpi `Ctrl + C` kopiointiin ja `Ctrl + V` liittämiseen toimii yleensä kaikkialla muualla graafisen käyttöliittymän puolella.

> [!WARNING] 
> Olet ehkä yrittänyt käyttää Windowsista tuttuja kopioi ` Ctrl + C ` ja liitä ` Ctrl + V ` toimintoja  terminaali-ikkunassa ja huomannut, että ne eivät toimi. Näillä pikanäppäimillä on eri merkitys Unix shell -ympäristössä, jotka annettiin monta vuotta ennen kuin ` Ctrl + C ` otettiin käyttöön leikepöydälle kopioimiseen ja ` Ctrl + V ` otettiin käyttöön leikepöydältä liittämiseen *Macintoshilla* vuonna 1983 ja *Windows 3:ssa* vuonna 1990.

**` Ctrl + C `** oli **keskeytys-näppäin** lähes kaikkialla Unixissa. Ja vielä nytkin sitä voidaan käyttää <ins>keskeyttämään</ins> nykyinen ohjelma tai toiminto terminaali-istunnossa.

**` Ctrl + V `** tarkoitti usein **sanatarkkaa lisäystä** (englanniksi **verbatim insert**); Toisin sanoen kyseistä pikanäppäin yhdistelmää seuraavan ohjausmerkin lisäystä kirjaimellisesti, suorittamatta syötettyyn ohjausmerkkiin liittyvää toimintoa (katso [Luku 3, Kappale: Ohjausmerkit](03-basic-terminal.md#ohjausmerkit-wiki-control)). Esimerkiksi ohjausmerkki ` Esc ` vaihtaa terminaali-istunnon komentotilaan, mutta ` Ctrl + V, Esc ` lisää Esc-ohjausmerkin ` ^[ ` nykyiseen lisäyskohtaan (englanniksi system caret).

### IBM-CUA

Aikaisemmat Windows-versiot (1.x ja 2.x) sekä IBM OS/2 tukivat vain **IBM Common User Access -näppäimiä** eli **` Ctrl + Ins `** kopiointia varten ja **` Shift + Ins `** liittämistä varten. Nämä pikanäppäimet ovat tuettuina kaikissa GNU/Linux- ja Windows-versioissa vielä nykyäänkin. [^ibm-cua]

[^ibm-cua]: [Wikipedia - IBM Common User Access, accessed 2025](https://en.wikipedia.org/wiki/IBM_Common_User_Access)

### Hiiren keskipainike

GNU/Linux työpöytäympäristöt tukevat (grafiikkapalvelimen kuten X.org:in tai Waylandin kautta) vaihtoehtoista tapa liittää sisältöä, **hiiren keskimmäistä painiketta** klikkaamalla.
- Kopioitava teksti maalataan ilman nimenomaista kopiointitoimintoa ja liitetään hiiren keskimmäisellä painikkeella, hiiren kursorin osoittamaan kohtaan. <!--Kokeile sitä, jos pystyt (jotkut työpöytäympäristöt, kuten Ubuntun Unity, eivät tosin enää tue sitä).-->
- Työpöytäympäristön ikkunassa olevat elementit pystyvät vastaanottamaan hiiren keskipainikkeen syötettä, vaikka lähde- ja kohdeikkunat eivät olisi kumpikaan enää kohdistettuna (englanniksi focused). Syötekohta (englanniksi input focus) seuraa niin sanotusti hiirtä.

<!--
- Tämä voi olla erittäin hyödyllinen ominaisuus tehdä asioita tehokkaasti, mutta se voi myös olla toisinaan hyvin ärsyttävä; erityisesti niille, joilla on herkkä hiiri.
    - Huomaat, että joka kerta, kun selaat hiiren pyörää liian nopeasti (mikä tarkoittaa keskimmäistä napsautusta), se liittää edellisen kopioidun sisällön tekstinkäsittelyohjelmaan, asiakirjoihin tai mihin tahansa muuhun tekstikenttään tietämättäsi.
    - Koska tämä on järjestelmätason ominaisuus, ei ole helppoa tapaa poistaa hiiren keskiklikkauksen kytkentäominaisuutta käytöstä. Onneksi on olemassa joitakin [kiertoteitä](https://www.maketecheasier.com/disable-middle-mouse-click-to-paste-feature-in-linux-quick-tips/) ja hakkereita, joita voidaan käyttää.
-->

<a id="text-selection"></a>

## 2.3 Tekstin valitseminen terminaalissa

> [!NOTE]
> Komentokäyttöliittymän tekstiä voi korostaa vain nykyaikaisissa graafisen työpöytäympäristön terminaali-emulaattori-sovelluksissa; Ja silloinkin vain hiirellä. Nuoremmat lukijat eivät ehkä tiedä, että aluksi päätelaitteissa näytön virkaa toimitti tulostin. Kun vuoden 1969 hitaasti paperille tulostavien päätelaitteiden aiheuttamat rajoitteet poistuivat, Unix kehittyi videonäyttöpäätteiden maailmaan, mutta monissa niistä ei vieläkään ollut nuolinäppäimiä tai toimintonäppäimiä. [^raymond]

Vielä nykyäänkin saattaa komentokäyttöliittymässä kohdata tilanteita, joissa ei voi käyttää hiirtä tekstin korostamiseen. Ja jos ei voi korostaa tekstiä, niin miten voi kopioida ja liittää sitä? Jonkinlaisena osittaisena ratkaisuna on kaikista unix-terminaaleista löytyvä mahdollisuus kopioida ja liittää aktiivisella komentorivillä seuraavin pikanäppäimin:

| Pikanäppäin | Toiminto |
|:--- |:--- |
| ` Ctrl + U ` | Leikkaa kaikki syötekohdistinta edeltävä (ja lisää leikepöytäpuskuriin). Jos syötekohdistin on komentorivin lopussa, toiminto leikkaa ja kopioi koko tekstin.|
| ` Ctrl + K ` | Leikkaa kaikki syötekohdistimen jälkeinen (ja lisää leikepöytdäpuskuriin). Jos syötekohdistin on komentorivin alussa, toiminto leikkaa ja kopioi koko tekstin. |
| ` Ctrl + W ` | Leikkaa syötekohdistinta edeltävä teksti enimmäiseen välilyöntiin asti (ja lisää leikepöytäpuskuriin). |
| ` Alt + D ` | Leikkaa syötekohdistimen jälkeinen enimmäiseen välilyöntiin asti (ja lisää leikepöytäpuskuriin). |
| **` Ctrl + Y `** | **Liitä** (viimeksi leikattu teksti). |

<a id="bash-history"></a>

### Komentohistoria <!--update internal links if changed-->

Komentotulkkiympäristö BASH muistaa sille annetut komennot. Komentohistoria tallentuu oletusarvoisesti tiedostoon ` ~/.bash_history ` eikä tyhjene istunnon sulkeutuessa.

Vanhoja komentoja voi hakea uudelleenkäytettäväksi nuolinäppäimin.
- Ylös-näppäin ` ▲ ` selaa vanhoja komentoja
- Alas-näppäin ` ▼ ` palataksesi takaisin uudempiin komentoihin.

Komentohistorian hyödyntäminen voi olla paljon tehokkaampaa kuin voisi olettaa:
- [Linux.fi ohjesivusto - Komentohistoria](https://www.linux.fi/wiki/Komentorivin_perusteet#Komentohistoria)
- [Chris Hoffman - How to use bash history, 2017](https://www.howtogeek.com/44997/how-to-use-bash-history-to-improve-your-command-line-productivity/)
- [Dave McKay - How to use the history command, 2024](https://www.howtogeek.com/465243/how-to-use-the-history-command-on-linux/)

<a id="directory-structure"></a>

## 2.4 Hakemistorakenne

GNU/Linux-järjestelmään tutustuessa, ehkä suurin hämmennys, Windowsiin tottuneille, on unix-tyylin hakemistorakenne. GNU/Linux-jakelut pyrkivät yleensä noudattamaan hakemistorakenne [Filesystem Hierarchy Standardia](https://refspecs.linuxfoundation.org/FHS_3.0/fhs-3.0.html). Vaikka peruskäyttäjän ei välttämättä tarvitse koskea hakemistorakenteeseen, on hyvä tietää mitä on missäkin.

Unix ja sen johdannaiset eivät käytä Microsoftin tapaa ryhmitellä hakemistoja asemien ja kiintolevyosioiden alle (kuten C, D, E ja niin edelleen). Esimerkiksi CD-levyltä luettaessa tai sille kirjoitettaessa, ei viitataan aseman liitäntäpisteeseen hakemistossa ` /media/ `. Unix hakemistorakenne perustui alun perin oletukseen, että jokaisella hakemistolla voi olla oma kiintolevy. Kotikäyttäjästä moinen voi tuntua absurdilta.

Jotkin hakemistot ovat virtuaalisia, kuten ` /sys/ ` rajapinta, joka kuvaa laitteiston ja ajureiden välisiä yhteyksiä. Jopa tulostin, hiiri ja näppäimistö ovat tiedostoja unix hakemistorakenteessa. Kaikki tämä ymmärrettävästi lisää hämmennystä. Se, että kaikki on tiedostoa, voidaan ensin ymmärtää ja lopulta arvostaa ohjelmointi-näkökulmasta.

### Erikoistermi: root

On hieman hämmentävää, että sanaa **root** käytetään kolmesta eri asiasta:
1. Pääkäyttäjä ` root `
2. Pääkäyttäjän kotihakemisto ` /root/`
3. Juurihakemisto ` / ` 

### Kotihakemistot

Pääkäyttäjän kotihakemisto on aina **` /root/ `**. Kaikkien muiden käyttäjien kotihakemistot sijaitsevat hakemistossa **` /home/ `**. Omaan kotihakemistoon kuten ` /home/tuula/ ` voi viitata vaihtoehtoisilla tavoilla kuten ` ~ `, ` $HOME ` ja ` /home/$USER `.

> Uuden kotihakemiston alustuksesta vastaa yleensä [xdg-user-dirs](https://www.freedesktop.org/wiki/Software/xdg-user-dirs/) ohjelma, jotta uuden käyttäjän kotihakemisto on valmiiksi täytetty kieliasetuksen mukaan nimetyillä perus alihakemistoilla (kuten Työpöytä, Asiakirjat, Lataukset, Kuvat).

> Ennen vanhaan, kun kiintolevyt olivat paljon pienempiä, ` /home/ ` oli eri levyllä ja se otettiin käyttöön (englanniksi mount) suhteellisen myöhään järjestelmän käynnistyttyä. Sitä vastoin ` /root/ ` katsottiin välttämättömäksi järjestelmän ylläpidon kannalta. Sen piti olla aina paikalla; Silloinkin kun *käyttäjän levyä* ei oltu otettu käyttöön.

<a id="software-applications"></a>

### Sovellusohjelmat <!--update internal links if changed-->

Kaikkia sovelluksia ei tallenneta samaan paikkaan, sillä jokaisella hakemistolla on oma käyttötarkoituksensa.

> Perinteisesti, järjestelmän toiminnalle välttämättömät, minimaaliset vaaditut, sovellustiedostot sijaitsivat hakemistoissa ` /bin/ `, ` /sbin/ ` ja ` /lib/ `. Muut, ei niin olennaiset, vapaavalintaiset sovellustiedostot ovat aina sijainneet muualla, kuten hakemistossa ` /usr/ `, joka otettiin perinteisesti käyttöön (englanniksi mount) vasta suhteellisen myöhään järjestelmän käynnistyttyä ja saattoi sijaita verkkolevyllä. Vastaavan toiminnallisuuden palauttaminen nykyaikaiseen järjestelmään olisi valtava vaiva, koska nykyaikaiset jakelut eivät enää erottele kunnolla hakemistoja ` /sbin/ `, ` /bin/ ` ja ` /lib/ `  vastineistaan hakemistossa ` /usr/ `.

#### Järjestelmäbinäärit

Perinteisesti, kaikille käyttäjille tarkoitetut kriittiset järjestelmäbinäärit (kuten ` $ ls ` ja ` $ find `), sijaitsivat hakemistossa **` /bin/ `** (Binaries).
- Nykyään ` /bin/ ` saattaa olla vain symlinkki hakemistoon ` /usr/bin/ `, jonne tällaiset binäärit on siirretty.

Perinteisesti, pääkäyttäjälle tarkoitetut kriittiset järjestelmäbinäärit, kuten ` $ adduser `, sijaitsivat hakemistossa **` /sbin/ `** (Superuser Binaries).
- Nykyään ` /sbin/ ` saattaa olla vain symlinkki hakemistoon ` /usr/sbin/ `, jonne tällaiset binäärit on siirretty.

> [!NOTE] 
> Tässä yhteydessä **binaaritiedosto** viittaa suoritettavaan tiedostoon, joka sisältää konekoodia tietokoneen suoritettavaksi (englanniksi executable).
>
> Muissa yhteyksissä binääritiedosto voi viitata mihin tahansa tiedostoon, joka koostuu jostain muusta kuin muotoilutiedottomasta suoraan ihmisen luettavissa tasrkoitetusta tekstistä (englanniksi plain text). Binääritiedosto on siis tietokoneen luettavaksi tarkoitettu tiedosto, ja voi sisältää lähes millaista tietoa tahansa kuten kuvia, tekstiä tai ääntä.

#### Jaetut kirjastot

Perinteisesti, hakemistoissa ` /bin/ ` ja ` /sbin/ ` sijaitsevien binäärien tarvitsevat kriittiset **jaetut kirjastot** (englanniksi shared library files) sijaitsivat hakemistossa **` /lib/ `**:ssä (Libaries).
- Nykyään ` /lib/ ` saattaa olla vain symlinkki hakemistoon ` /usr/lib/ `, jonne tällaiset kirjastot on siirretty.

> [!NOTE] 
> Tässä yhteydessä **kirjasto** tarkoittaa kokoelmia, aliohjelmia, sekä luokkia, joita käytetään tietokoneohjelmien modulaarisessa kehittämisessä ja ohjelmien suorittamisen aikana. Kirjastoissa olevia (ali)ohjelmia ei yleensä suoriteta itsenäisesti, vaan niissä olevia palveluita käytetään itsenäisesti suoritettavien ohjelmien apuna. [^wiki-kirjasto]

[^wiki-kirjasto]: [Wikipedia - Kirjasto (tietotekniikka), accessed 2025](https://fi.wikipedia.org/wiki/Kirjasto_(tietotekniikka))

#### Lisäsovellukset

Perinteisesti ja vielä nykyäänkin, paketinhallinnan kautta asennetut lisäsovellukset sijaitsevat hakemistossa **` /usr/ `** (Unix Shared Resources).

Ennen vanhaan UNIX-toimittajat (kuten AT&T, Sun, DEC) ja kolmannen osapuolen toimittajat käyttivät hakemistoa ` /opt/ ` lisähinnasta ostetuille sovelluksille (tästä nimi **option packages**).
- Kaikissa Unix-muunnoksissa, kuten Berkeley BSD UNIXissa, ei ollut ` /opt/ ` hakemistoa, mutta niissä käytettiin ` /usr/local/ ` hakemistoa itse asennettaville ohjelmille.
- Nykyään hakemistoon **` /opt/ `** (Option packages) asentuvat jotkin kolmannen osapuolen ohjelmat kuten ` *.deb ` paketista asennetut [Vivaldi Browser](https://vivaldi.com/download/), [Master PDF Editor](https://code-industry.net/masterpdfeditor/) ja [ONLYOFFICE Desktop Editors](https://www.onlyoffice.com/download-desktop.aspx?from=desktop).

#### Hakemisto /usr/

Hakemisto ` /usr/ ` sisältää vain jaettavaa ja vain luettavaa tietoa, ei asetuksia eikä lokitietoja. Kaikki isäntäkohtaiset tai ajan myötä muuttuvat tiedot tallennetaan muualle. Tärkeimmät alihakemistot ovat:

| Hakemisto | Käyttötarkoitus |
|:--- |:--- |
| **` /usr/sbin/ `** <br>= **` /sbin/ `** | <ins>Useimmat pääkäyttäjän binäärit</ins> sijaitsevat hakemistossa ` /usr/sbin/ `. Alihakemistoja ei saa olla. [^fhs-sbin] [^fhs-usr-sbin] |
| **` /usr/bin/ `** <br>= **` /bin/ `** | <ins>Useimmat binäärit</ins> sijaitsevat hakemistossa ` /usr/bin/ `, joka on järjestelmän ensisijainen suoritettavien komentojen hakemisto. Alihakemistoja ei saa olla. [^fhs-bin] [^fhs-usr-bin] |
| **` /usr/lib/ `** <br>= **` /lib/ `** | GNU/Linux-järjestelmässä on paljon jaettuja **kirjastoja**, jotka pystyvät tekemään monia hyödyllisiä asioita. Moni ohjelma voi käyttää samoja kirjastoja. Kirjaston kokoelmia, aliohjelmia, luokkia ja jopa binääritiedostoja hakemistossa ` /usr/lib/ ` ei suoriteta itsenäisesti, vaan niissä olevia palveluita käytetään itsenäisesti suoritettavien ohjelmien apuna. Sovellukset voivat käyttää yhtä alihakemistoa. [^fhs-usr-lib] [^fhs-lib] |
| **` /usr/include/ `** | Lähinnä C-ohjelmointikielen **otsikkotiedostot** sijaitsevat täällä (englanniksi **header files**). Otsikkotiedostoilla on tavallisesti pääte ` *.h* `, mutta toisinaan näkee myös muita päätteitä, kuten ` *.hpp* ` tai ` *.d* `, tai ilman päätettä. Otsikkotiedostojen tarkoitus on vaikea käsittää, jos ei tunne C-ohjelmointikieltä. Otsikkotiedosto sisältää funktioiden julistuksia, tyyppimäärityksiä ja muita yleisiä julistuksia, jotka jaetaan useissa lähdetiedostoissa. Sen avulla voidaan erottaa rajapinta (funktioiden prototyypit) toteutuksesta (funktiomääritykset). [^fhs-usr-include] |
| **` /usr/share/ `** | Prosessoriarkkitehtuurista (kuten x86 32-bit, x86_64 64-bit, ARM 32-bit, ARM 64-bit, MIPS) riippumattomat, ei-suoritettavat (non executable), staattiset sovellusten datatiedostot ovat **jakokelpoisia** tietyn käyttöjärjestelmän kaikilla arkkitehtuurialustoilla. Eli suurin osa <ins>ohjelmien tarvitsemasta datasta, jota ei tarvitse muuttaa</ins>, sijaitsee täällä. Hakemistoon ` /usr/share/ ` tallennetun tiedon on oltava puhtaasti staattista, kuten käyttöohjeet, eri kielten sanaluettelot, XML-, HTML- ja postScript määrittelytiedostot, ICC-värinhallintatiedostot. Kaikki muokattavissa oleva tieto tallennetaan muualle. [^fhs-usr-share] |

[^fhs-sbin]: [Filesystem Hierarchy Standard: System binaries](https://refspecs.linuxfoundation.org/FHS_3.0/fhs-3.0.html#sbinSystemBinaries)

[^fhs-usr-sbin]: [Filesystem Hierarchy Standard: Non-essential standard system binaries](https://refspecs.linuxfoundation.org/FHS_3.0/fhs-3.0.html#usrsbinNonessentialStandardSystemBi)

[^fhs-bin]: [Filesystem Hierarchy Standard: Essential user command binaries)](https://refspecs.linuxfoundation.org/FHS_3.0/fhs-3.0.html#binEssentialUserCommandBinaries)

[^fhs-usr-bin]: [Filesystem Hierarchy Standard: Most user commands](https://refspecs.linuxfoundation.org/FHS_3.0/fhs-3.0.html#usrbinMostUserCommands)

[^fhs-usr-lib]: [Filesystem Hierarchy Standard: Libraries for programming and packages](https://refspecs.linuxfoundation.org/FHS_3.0/fhs-3.0.html#usrlibLibrariesForProgrammingAndPa)

[^fhs-lib]: [Filesystem Hierarchy Standard: Essential shared libraries and kernel modules](https://refspecs.linuxfoundation.org/FHS_3.0/fhs-3.0.html#libEssentialSharedLibrariesAndKern)

[^fhs-usr-include]: [Filesystem Hierarchy Standard: Header files included by C programs](https://refspecs.linuxfoundation.org/FHS_3.0/fhs-3.0.html#usrincludeHeaderFilesIncludedByCP)

[^fhs-usr-share]: [Filesystem Hierarchy Standard: Architecture-independent data](https://refspecs.linuxfoundation.org/FHS_3.0/fhs-3.0.html#usrshareArchitectureindependentData)

> [!TIP]
> Joskus voi olla hyödyllistä käyttää kirjastofunktioita omissa ohjelmissa. Esimerkiksi suosittu [VLC mediasoitin](https://www.videolan.org) sisältää monipuolisen [libvlc kirjaston](https://wiki.videolan.org/LibVLC/).
> Tämä voi onnistua vaikka kirjasto olisi tehty eri ohjelmointikielillä kuin oma ohjelma. Esimerkiksi C-kielen kirjastofunktioita voidaan käyttää BASIC-kielisessä [Gambas kehitysympäristössä](https://en.wikipedia.org/wiki/Gambas). [^gambas-wiki] [^gambas-extern]

[^gambas-wiki]: [Wikipedia - Gambas, accessed 2024](https://en.wikipedia.org/wiki/Gambas)

[^gambas-extern]: [Gambas Documentation - How To Interface Gambas With External Libraries, accessed 2024](https://gambaswiki.org/wiki/howto/extern)

#### Ympäristömuuttuja: PATH [^fi-path]

[^fi-path]: [Linux.fi ohjesivusto - PATH, accessed 2025](https://www.linux.fi/wiki/PATH)

Ympäristömuuttuja PATH sisältää luettelon hakemistoista, jotka komentotulkki tutkii, etsiessään suoritettavaksi nimettyä ohjelmatiedostoa. Muualla sijaitsevan ohjelmatiedoston käynnistäminen edellyttää absoluuttisen tai suhteellisen tiedostopolun lisäystä osaksi käynnistyskäskyä, pelkän tiedostonimen sijaan.

Jos halutaan käynnistää suoritettava tiedosto ` ~/.local/bin/ohjelma `, niin jopa oltaessa samassa hakemistosta, joutuu ohjelman käynnistääkseen kirjoittamaan tiedostopolun jossain muodossa:

```
# a) 
tuula@läppäri ~ $ cd .local/bin↵  # Siirrytään ohjelmakansioon
tuula@läppäri bin $ ohjelma↵      # Pelkkä tiedostonimi ei riitä
bash: ohjelma: command not found  # Ohjelma ei käynnisty

# b) Suhteellinen tiedostopolku toimii
tuula@läppäri ~/.local/bin/ $ ./ohjelma↵ # Ohjelma käynnistyy

# c) Suhteellinen tiedostopolku toimii
tuula@läppäri bin $ cd ..↵   # Siirrytään pois ohjelmakansiosta
tuula@läppäri .local $ bin/ohjelma↵   # Ohjelma käynnistyy

# d) Absoluuttinen tiedostopolku toimii
tuula@läppäri .local $ ~/.local/bin/ohjelma↵ # Ohjelma käynnistyy
```

Jos hakemisto ` ~/.local/bin/ ` olisi listattu ympäristömuuttujassa PATH, niin ohjelman voisi käynnistää pelkällä tiedostonimellä kutsuen ` $ ohjelma↵ `.

Komento ` $ echo $PATH↵ ` paljastaa ympäristömuuttujan PATH sisältämät hakemistot:

```
$ echo "$PATH" | tr ':' '\n'↵
/home/user/.local/bin
/usr/sbin
/usr/bin
/snap/bin
```

### Dynaaminen data

> [!NOTE]
> Staattinen ja dynaaminen data on jaoteltu eri hakemistoihin.
> - **Dynaaminen data** on dataa, joka muuttuu ja jota kertyy reaaliajassa.
> - **Staattinen data** pysyy suhteellisen muuttumattomana, syntyy yhdellä kerralla, tietyllä ajanhetkellä, eikä muutu ajan edetessä.

Hakemisto **` /var/ `** (englanniksi variable = muuttuva) on tarkoitettu järjestelmän ja sovellusten dynaamisen eli muuttuvan datan tallentamiseen. Tällaisten hakemistojen ja niiden sisältämien tiedostojen sisältö riippuu ajanhetkestä. Dynaamista dataa kertyy esimerkiksi lokitiedostoista.

Sovellukset eivät yleensä saa lisätä hakemistoja ` /var/ `:n ylimmälle tasolle. Sen sijaan käytetään seuraavia alihakemistoja tai sym-linkkejä:

| Hakemisto | Käyttötarkoitus | RAM<br>-levy |
|:--- |:--- | --- |
| **` /var/cache/ `** | Sovelluksen **välimuisti** tarkoittaa <ins>tietoa, joka on tallennettu palvelemaan tulevia pyyntöjä nopeammin</ins>. Välimuistiin tallennettu tieto voi olla aikaisemman laskennan tulos tai kopio muualle tallennetusta tiedosta. Toisin kuin puskuri-data hamekistossa ` /var/spool/ `, niin sovelluksen on voitava luoda tai palauttaa poistettu välimuisti-data uudelleen ilman tietojen menetystä. Tietojen on pysyttävä kelvollisena sovelluksen käyttökertojen ja tietokoneen uudelleenkäynnistyksen välillä. [^fhs-cache][^wiki-cache] |   |
| **` /var/lib/ `** | Tilapäiseen varastointiin sovellusten omille suorituksen aikaisille sisäisille **tilatiedoille**, <ins>joita ei saa paljastaa tavallisille käyttäjille</ins>. Sovelluksen (tai toisiinsa liittyvien sovellusten ryhmän) tulisi yleensä käyttää alihakemistoa tietojaan varten, mutta käytössä on myös ` /var/lib/misc/ ` tilatiedostoille, jotka eivät tarvitse omaa alihakemistoa. [^fhs-lib] |   |
| ` /var/lock/ ` <br>= **` /run/lock/ `** | Jotkin ohjelmat noudattavat käytäntöä luoda **lukitustiedosto** <ins>ilmaisemaan tietyn laitteen tai tiedoston käytön</ins>, jotta muut ohjelmat voivat välttää käyttämästä lukittua laitetta tai tiedostoa samanaikaisesti. [^fhs-lock][^tldp-var] | ✓ |
| **` /var/log/ `** | Useista toiminnoista pidetään tapahtumarekisteriä eli lokitiedostoa, joko suoraan tähän hakemistoon tai sopivaan alihakemistoon. **Lokiviestejä** <ins>voidaan käyttää ongelmien selvittämiseen, sekä järjestelmän toiminnan seurantaan ja ymmärtämiseen</ins>. [^fhs-log] |   |
| **` /var/opt/ `** | Tarkoitettu hakemistoon ` /opt/ ` asennettujen <ins>*optiosovellusten* dynaamisen datan taltiointitarpeelle</ins>. Tieto tallennetaan optiosovelluksen mukaan nimettyyn alihakemistoon. [^fhs-opt] |   |
| ` /var/run/ ` <br>= **` /run/ `** | Sisältää <ins>suorituksenaikaista käynnissä oleviin järjestelmäprosesseihin liittyvää väliaikaista dataa</ins>. On käytettävissä jo käynnistysprosessin alkuvaiheessa, jota tietyt palvelut ja prosessit saattavat tarvita ennen kuin koko käyttöjärjestelmä on ladattu. Tyhjennetään järjestelmän uudelleenkäynnistyksen yhteydessä. On luotu väliaikaisena tmpfs-levyosiona keskusmuistiin (RAM), joka näyttää asennetulta tiedostojärjestelmältä, jotta olisi helpommin saatavilla ja hallittavissa. Ei kirjoitusoikeutta etuoikeudettomille käyttäjille. Kirjoitusoikeus käyttäjäkohtaisissa alihakemistoissa vain omistajalla. [^fhs-run] [^sandra] | ✓ |
| **` /var/spool/ `** | Puskuri-data (englanniksi **spool** = kelata, puolata) sisältää <ins>sovellus-dataa, joka odottaa jatkokäsittelyä</ins> kuten tulostusjono. Usein puskuri-data poistetaan sen jälkeen, kun ne on käsitelty. [^fhs-spool] |   |
| **` /var/tmp/ `** | Käytettävissä ohjelmille, jotka tarvitsevat <in>väliaikaisia tiedostoja tai hakemistoja (englanniksi temporary), jotka säilyvät tietokoneen uudelleenkäynnistysten välillä</in>. Tässä hakemistossa olevia tiedostoja ja hakemistoja ei saa poistaa järjestelmän käynnistyksen yhteydessä. [^fhs-tmp] |   |

[^wiki-cache]: [Wikipedia - Cache (computing)](https://en.wikipedia.org/wiki/Cache_(computing))

[^sandra]: [Sandra Henry-Stocker - Exploring /run on Linux, published 2019](https://www.networkworld.com/article/967547/exploring-run-on-linux.html)

[^fhs-spool]: [Filesystem Hierarchy Standard: Application spool data](https://refspecs.linuxfoundation.org/FHS_3.0/fhs-3.0.html#varspoolApplicationSpoolData)

[^fhs-tmp]: [Filesystem Hierarchy Standard: Temporary files](https://refspecs.linuxfoundation.org/FHS_3.0/fhs-3.0.html#vartmpTemporaryFilesPreservedBetwee)

[^fhs-run]: [Filesystem Hierarchy Standard: Run-time variable data](https://refspecs.linuxfoundation.org/FHS_3.0/fhs-3.0.html#varrunRuntimeVariableData)

[^fhs-opt]: [Filesystem Hierarchy Standard - Variable data for /opt](https://refspecs.linuxfoundation.org/FHS_3.0/fhs-3.0.html#varoptVariableDataForOpt)

[^fhs-lock]: [Filesystem Hierarchy Standard - Lock files](https://refspecs.linuxfoundation.org/FHS_3.0/fhs-3.0.html#varlockLockFiles)

[^tldp-var]: [Linux System Administrators Guide - The /var filesystem](https://tldp.org/LDP/sag/html/var-fs.html)

[^fhs-log]: [Filesystem Hierarchy Standard - Log files and directories](https://refspecs.linuxfoundation.org/FHS_3.0/fhs-3.0.html#varlogLogFilesAndDirectories)

[^fhs-cache]: [Filesystem Hierarchy Standard - Application cache data](https://refspecs.linuxfoundation.org/FHS_3.0/fhs-3.0.html#varcacheApplicationCacheData)

### RAM-levy [^ramdisk]

[^ramdisk]: [Riccardo - RAM Disk on Linux, 2011](https://linuxaria.com/pills/ram-disk-on-linux)

Kaikki nykyaikaiset GNU/Linux-jakelut tarjoavat osan keskusmuistista RAM-levynä. Se on luotu väliaikaisena tmpfs-levyosiona liityntäpintaan **` /dev/shm/ `**, joka näyttää asennetulta tiedostojärjestelmältä, jotta olisi helpommin saatavilla ja hallittavissa.
- Sitä voidaan käyttää aivan kuten tavallista levytilaa; luoda ja käsitellä tiedostoja ja hakemistoja, mutta paremmalla suorituskyvyllä verrattuna siihen, että tallennettaisiin kiintolevylle.
- Se on tehokas keino jakaa ja välittää dataa ohjelmien välillä. Yksi ohjelma luo muistin osan, jota muut prosessit voivat käyttää. Siitä nimi shared memory (shm) eli jaettu muisti.
- Kehittynyt kuvankatseluohjelma voisi käyttää sitä zip-arkistoista poimittujen tiedostojen väliaikaisena tallennuspaikkana, paitsi nopeushyödyn vuoksi, niin myös käyttäjän kiintolevyn tai SSD-levyn tarpeettoman kulumisen rajaamiseen.
- Koska tiedot sijaitsevat RAM-muistissa, ne tyhjennetään virran katkeamisen yhteydessä, olipa se tahallista (tietokoneen uudelleenkäynnistys tai sammutus) tai tahatonta (sähkökatkos tai järjestelmän kaatuminen). [^wikiram]

[^wikiram]: [Wikipedia - RAM drive, accessed 2024](https://en.wikipedia.org/wiki/RAM_drive)

<!-- The virtual filesystem types such as tmpfs, don't take up disk space or occupy more RAM than used. Size and how much is available is just upper limit as to how much RAM it may use.-->

### Siirrettävän tietovälineen liityntäkohta <!--update internal links if changed-->

Siirrettävän tietovälineen käyttöönotto taikka liittäminen (englanniksi **mounting**) on edellytys tiedostojärjestelmän sisällön näyttämiselle käyttöjärjestelmässä. Jos kiintolevyosiota tai DVD-levyä ei ole liitetty, se näkyy ainoastaan laitetiedostona hakemiston ` /dev/ ` alla. DVD-elokuvan toistaminen tai tyhjälle DVD-levylle kirjoitus eivät edellytä liittämistä, mutta liittäminen vaaditaan, mikäli levyn sisältöä halutaan käsitellä tiedostonhallinta-ohjelmassa. [^fi-mount]

[^fi-mount]: [Linux.fi ohjesivusto - mount, accessed 2025](https://www.linux.fi/wiki/Mount)

| Hakemisto | Käyttötarkoitus |
|:--- |:--- |
| **` /media/ `** or <br>` /run/media/ ` | Liityntäkohdat fyysiselle medialle kuten Blu-ray levyt, ulkoiset kiintolevyt, USB-muistitikut ja sisäiset kiintolevyosiot (kuten mahdollisen rinnalle asennetun toisen käyttöjärjestelmän levyosio). [^fhs-media] |
| **` /mnt/ `** | Liityntäkohdat tilapäisesti asennetuille tiedostojärjestelmille kuten verkkolevyt tai [VMware Shared Folder](https://techdocs.broadcom.com/content/broadcom/techdocs/us/en/vmware-cis/desktop-hypervisors/workstation-pro/17-0/using-vmware-workstation-player-for-linux-17-0/setting-up-shared-folders-for-a-virtual-machine-linux/mounting-shared-folders-in-a-linux-guest-linux.html) eli paikallisen virtuaalikoneen ja isäntäjärjestelmän välitse jaettu yhteishakemisto. [^fhs-mnt] |

[^fhs-media]: [Filesystem Hierarchy Standard - Mount point for removable media](https://refspecs.linuxfoundation.org/FHS_3.0/fhs-3.0.html#mediaMountPoint)

[^fhs-mnt]: [Filesystem Hierarchy Standard - Mount point for a temporarily mounted filesystem](https://refspecs.linuxfoundation.org/FHS_3.0/fhs-3.0.html#mntMountPointForATemporarilyMount)

### Laitteiston liityntäkohta

| Hakemisto | Käyttötarkoitus |
|:--- |:--- |
| **` /sys/ `** (System) | Virtuaalinen hakemisto joka paljastaa liityntäkohtia laitteistoon, ajureihin ja järjestelmäytimeen. Näyttää asennetulta tiedostojärjestelmältä, jotta olisi helpommin saatavilla ja hallittavissa. [^fhs-sys] |
| **` /dev/ `** (Devices) | Virtuaalinen hakemisto joka paljastaa liityntäkohtia sekä oikeaan laitteistoon kuten kiintolevyosioihin, että erikoistoimintoihin kuten satunnaislukugeneraattoriin. [^fhs-dev] Katso [Kappale: Laitetiedostot](#laitetiedostot) ja [Kappale: Erikoislaitetiedostot](#erikoislaitetiedostot). |

[^fhs-sys]: [Filesystem Hierarchy Standard: Kernel and system information virtual filesystem](https://refspecs.linuxfoundation.org/FHS_3.0/fhs-3.0.html#sysKernelAndSystemInformation)

[^fhs-dev]: [Filesystem Hierarchy Standard: Device files](https://refspecs.linuxfoundation.org/FHS_3.0/fhs-3.0.html#devDeviceFiles)

Kaikki nykyaikaiset GNU/Linux-jakelut tarjoavat osan keskusmuistista RAM-levynä. Se on luotu väliaikaisena tmpfs-levyosiona liityntäpintaan **` /dev/shm/ `**, joka näyttää asennetulta tiedostojärjestelmältä, jotta olisi helpommin saatavilla ja hallittavissa.

### Hakemisto ≠ Kansio

Kun Window 95 julkaistiin vuonna 1995, Microsoft näytti korvaavan vakiintuneen sanan *hakemisto* toisella sanalla, *kansio*. Tapa levisi 1980-luvun puolivälin Macintosh-käyttöjärjestelmästä, johon oppi haettiin Xeroxin Palo Alto Research Centerin pioneerityöstä.

Usein kansiolla ja hakemistolla tarkoitetaan pohjimmiltaan samaa asiaa, mutta kansio on kuitenkin monipuolisempi määre.
- **Hakemisto** (englanniksi **Directory**) on tiedostojärjestelmän osa, joka sisältää tiedostoja ja muita hakemistoja.
- **Kansio** (englanniksi **Folder**) on graafisen käyttöliittymän kielikuva. Toisin kuin hakemisto, kansio voi olla virtuaalinen konstruktio, joka ei välttämättä vastaa suoraan tiettyä tallennuspaikkaa ja todellista hakemistoa tiedostojärjestelmässä. Tässä mielessä uudella termillä on oikeutuksensa.
    - Microsoft Windows käyttää kansioiden käsitettä auttamaan tietokoneen sisällön esittämisessä käyttäjälle tavalla, joka vapauttaa käyttäjän absoluuttisten hakemistopolkujen käsittelystä. **Ohjauspaneeli** tarjoaa pääsyn erilaisiin järjestelmän ominaisuuksiin ja asetuksiin. **Roskakori** tarjoaa käyttöliittymän poistettujen tiedostojen hallintaan. **Oma Tietokone** näyttää liitetyt asemat ja laitteet.

### Kaikki on edustettuna tiedostoina [^hoffman-2016]

[^hoffman-2016]: [Chris Hoffman - What does "everything is a file" mean in linux?, published 2016](https://www.howtogeek.com/117939/htg-explains-what-everything-is-a-file-means-on-linux/)

Unixeissa kaikki vaikuttaa olevan edustettuna tiedostoina. Hakemistot ovat tiedostoja. Järjestelmätiedot ovat tiedostoja. Tulostin, hiiri ja näppäimistö ovat tiedostoja. Näyttö on tiedosto. Satunnaislukugeneraattori on tiedosto. Määrittelevä piirre, että kaikki on edustettuna tiedostoina, auttaa ymmärtämään, miten unixit ja sen johdannaiset toimivat. Lähes kaikki näkyy ja käyttäytyy tiedostojärjestelmässä tiedostoina, jotta data ja toiminnallisuus olisi helpommin saatavilla ja hallittavissa.

> [!TIP]
> Et tarvitse erityistä komentoa tai ohjelmaa, jos haluat vaikkapa löytää tietoa tietokoneesi suorittimesta. Voit yksinkertaisesti lukea erikoistiedoston ` /proc/cpuinfo ` sisällön ikään kuin se olisi tekstitiedosto. Voit käyttää tavallisia komentoja tulostaaksesi tekstisisällön terminaaliin ` $ cat /proc/cpuinfo `. Tai jopa avata sen tekstieditoriin, tuplaklikkaamalla sitä tiedostonhallinta-ohjelmassa.
> Huomaa, että ` /proc/cpuinfo ` ei ole aito tekstitiedosto. Käyttöjärjestelmäydin ja ` /proc/ ` hakemisto paljastavat meille tämän tiedon tässä muodossa ”tiedostona”. Näin voimme käyttää yksinkertaisia työkaluja tietojen tarkasteluun ja käsittelyyn. Sama hakemisto sisältää myös muita vastaavia erikoistiedostoja kuten ` /proc/uptime ` ja ` /proc/version `.

<a id="device-files"></a>

### Laitetiedostot <!--update internal links if changed-->

Windowsissa sisäiset tallennusasemat ja optiset asemat esitetään asemakirjaimin kuten C: D: E: G: H: Unixissa samojen laitteiden liityntäpinnat sijaitsevat hakemistossa ` /dev/ ` erikoisesti nimettyinä erikoistiedostoina. [^hoffman-2016] Johdatus sisäisten tallennusasemien viittauksia hakemistossa ` /dev/ ` onnistunee parhaiten esimerkein:
- Jos ensimmäisellä *sisäisellä SATA SSD -tallennusasemalla* olisi kolme ensisijaista osiota, ne nimettäisiin ja numeroitaisiin ` /dev/sda1 `, ` /dev/sda2 ` ja ` /dev/sda3 `.
- Jos ensimmäisellä *sisäisellä SATA HDD -tallennusasemalla* olisi kolme ensisijaista osiota, ne nimettäisiin ja numeroitaisiin seuraavasti: ` /dev/hda1 `, ` /dev/hda2 ` ja ` /dev/hda3 `.
- Jos ensimmäisellä *sisäisellä M.2 SSD -tallennusasemalla* olisi kolme ensisijaista osiota, ne nimettäisiin ja numeroitaisiin seuraavasti: ` /dev/nvme0n1p1 `, ` /dev/nvme0n1p2 ` ja ` /dev/nvme0n1p3 `.
- Sisäinen Blu-ray-asema voitaisiin nimetä ja numeroida ` /dev/scd0 `.
- Nämä kaikki ovat vain viittauksia asemiin ja osioihin. Tietosisältö paljastuu muualla kiinnityspisteiden kautta (katso [Kappale: Siirrettävän tietovälineen liityntäkohta](#siirrettävän-tietovälineen-liityntäkohta)).

> [!NOTE]
> Tämä sisäisen tallennustilan nimeämiskäytännön tunteminen on ensiarvoisen tärkeää käyttöjärjestelmän asennusvaiheessa. Jolloin joutuu valitsemaan osiot ja mahdollisesti tekemään muutoksia olemassa oleviin osioihin osiointityökalulla [GParted](https://en.wikipedia.org/wiki/GParted).

<a id="special-device-files"></a>

### Erikoislaitetiedostot <!--update internal links if changed-->

Hakemisto ` /dev/ ` sisältää fyysisten laitteiden liityntäpintojen lisäksi erikoislaitetiedostoja kuten:

| Tiedosto | Käyttötarkoitus |
|:--- |:--- |
| **` /dev/random `** | on erikoislaitetiedosto josta lukeminen palauttaa satunnaisluvun. Aidosti satunnaisten lukujen tuottaminen on teknisesti haastavaa. Linuxin ` /dev/random ` lupaa luotettavaa satunnaisuutta 256 bitin tarkkuuteen asti, mikä on tarpeen kryptografisten avainten tuottamiseen. [^man7-random] |
| **` /dev/zero `** | on erikoislaitetiedosto josta lukeminen palauttaa pyydetyn määrän nollia. Käyttötarkoituksia ovat tallennuslaitteiden pyyhkiminen sen varmistamiseksi, että jäljelle jääviä tietoja ei jää, suurten tyhjien tiedostojen kuten levykuvien luominen, muisti- ja tallennusskenaarioiden simulointi testauksessa, tallennussuorituskyvyn vertailuanalyysi. [^fhs-special] |
| **`/dev/null `** | on erikoislaitetiedosto johon kirjoitettu data häviää. [^fhs-special] [^hoffman-2016] |

[^man7-random]: [Michael Kerrisk - Linux manual page, accessed 2024](https://www.man7.org/linux/man-pages/man7/random.7.html)

> [!TIP]
> Oletusarvoisesti komentorivityöskentely tuottaa virheilmoituksia ja muita tulosteita, jotka siirtyvät vakiotulosteeseen ja siis yleensä näyttöruudulle. Halutessaan suorittaa komentoja tulosteista piittaamatta, voi ohjata tulosteet ` /dev/null `:iin. Tulosteen ohjaaminen kyseiseen erikoislaitetiedostoon hävittää tulosteen välittömästi.
> - Sen sijaan, että jokaisella komennolla olisi oma *hiljainen tila*, tämä menetelmää voi käyttää minkä tahansa komennon kanssa näin ` $ komento > /dev/null↵ ` [^hoffman-2016]

[^fhs-special]: [Filesystem Hierarchy Standard: Devices and special files](https://refspecs.linuxfoundation.org/FHS_3.0/fhs-3.0.html#devDevicesAndSpecialFiles)

<a id="shell-environment"></a>

## 2.5 Shell-ympäristö [^raymond]

Toimintaympäristöllä tarkoitetaan kokonaisuutta, jossa toiminta tapahtuu.

### Ohjaustiedot

Perinteisesti unix-sovellus etsii **ohjaustietoja** (englanniksi **control information**) viidestä paikasta käynnistysympäristössään:
1. Yhteiset [määritystiedostot](#määritystiedostot) hakemistossa ` /etc/ `.
2. Järjestelmän asettamat [ympäristömuuttujat](#ympäristömuuttujat).
3. Käyttäjäkohtaiset [määritystiedostot](#määritystiedostot) kotihakemistossa.
4. Käyttäjän asettamat [ympäristömuuttujat](#ympäristömuuttujat).
5. Ohjelmakutsun perään kirjoitetut [komentoriviargumentit](03-basic-terminal.md#erikoismerkki-viiva--).

On olemassa vahva perinne, jonka mukaan hyvin käyttäytyvät ohjelmat tarkastelevat ohjaustietoja juuri edellä mainitussa järjestyksessä. Tällöin myöhemmät, paikallisemmat, asetukset syrjäyttävät aiemmat, globaalit, asetukset. Eli ympäristöasetukset ovat yleensä painoarvoltaan dotfile-asetusten yläpuolella, mutta nekin voidaan ohittaa komentoriviargumentein. Näin ohjelmaa voidaan tarvittaessa skriptata luotettavasti määritellyllä käyttäytymisellä, riippumatta siitä miten ympäristö on asetettu. <!--Aikaisemmin löydetyt asetukset voivat auttaa ohjelmaa laskemaan sijainteja myöhempiä asetustietojen hakuja varten. On olemassa tiettyjä poikkeuksia kuten komentoriviargumentit, jotka määrittävät, mistä dotfile pitäisi löytää.-->

Se, mitä näistä paikoista tarkastellaan, riippuu siitä, kuinka paljon konfiguraatiota ohjelma tarvitsee.
- Välttämättä ohjelmilla ei ole lainkaan tarvetta säilyttää asetuksia kutsujen välillä. Hyviä esimerkkejä tästä mallista ovat ` $ ls `, ` $ grep ` ja ` $ sort `. Ne konfiguroidaan kokonaan komentoriviargumentein.
- Toisessa ääripäässä ovat ohjelmat, jotka hyödyntävät monipuolisesti määritystiedostoja sekä ympäristömuuttujia. Ja normaalikäyttöön saattaa liittyä vain vähän, tai ei lainkaan komentoriviargumenttien käyttöä. Hyviä esimerkkejä tästä mallista ovat sähköposti- ja palomuuriohjelmat.

### Määritystiedostot <!--update internal links if changed-->

**Konfigurointi** viittaa prosessiin, jossa ohjelmiston asetuksia säädetään tiettyjen vaatimusten ja tarpeiden mukaan. **Konfigurointi-tiedosto** tai **määritystiedosto** tai **asetustiedosto** (englanniksi **configuration file**) sisältää tällaisia ohjelmiston muokattavuuteen liittyviä asetuksia.

> [!NOTE]
> Unixeissa määritystiedostot ovat tekstitiedostoja, jotta ne ovat helposti sekä koneen että ihmisen luettavissa ja muokattavissa.

#### Suoritettavat määritystiedostot

Osa määritystiedostoista on komentotulkilla ajettavia komentosarjoa tai skriptejä, eräänlaisia käynnistystiedostoja. Komentotulkki siis suorittaa joukon komentoja jo käynnistyksen yhteydessä.
- Tiedostonimiä tarkkaillessa törmää välillä tiedostopäätteeseen "rc", joka tulee sanoista **run commands** eli aja komennot. Komentosarjamuotoisista määritystiedostoista käytetäänkin nimitystä **runcom file** tai **run-control file**.

Eri runcom-tiedostoja luetaan tai jätetään lukematta käynnistettävän komentotulkki-istunnon tyypin mukaan (katso [Wikipedia - Unix shell configuration files](https://en.wikipedia.org/wiki/Unix_shell#Configuration_files)). Komentotulkkiympäristö muodostuu siis erilaiseksi sen mukaan
- Onko kyseessä shell-ohjelman käyttö taustalla erilaisten sovellusohjelmien tai järjestelmäpalveluiden toimesta, ilman suoraa vuorovaikutusta käyttäjän kanssa (englanniksi **non-interactive shell session**).
- Käynnistyykö pääteistunto ilman sisäänkirjautumista (**non-login shell session**), mikä tapahtuu tyypillisesti käynnistäessä pääteistunto graafisessa käyttöliittymässä terminaali-ikkunaan.
- Kysytäänkö käyttäjätunnusta ja salasanaa (englanniksi **login shell session**), mikä tapahtuu tyypillisesti siirryttäessä graaafisesta työpöytäympäristöstä tekstimuotoiseen TTY-ympäristöön.

> [!NOTE]
> Lyhenne **TTY** tulee englannin kielen sanasta teletype ja viittaa prosessia ohjaavaan päätelaitteeseen. Käyttöjärjestelmä osoittaa tässä ikänsä ja tarjoaa edelleen tyypillisesti noin 7 virtuaalista päätelaitetta, joiden välillä voidaan vaihtaa pikanäppäimin ` Ctrl + Alt + F# `.
> Aikanaan ne olivat ohjelmien moniajoa mahdollistava komentorivikäyttöliittymän vastine graafisen käyttöliittymän ikkunoille. Yhdellä TTY:llä saattoi pitää auki käyttöohjetta. Yksi saattoi suorittaa pitkäkestoista komentoa. Ja vielä jäi useampi vapaa liittymä muuhun samanaikaiseen käyttöön. Nykyäänkin TTY:t voivat olla erittäin hyödyllisiä, jos vaikkapa graafinen työpöytäympäristö jumiutuu.

> [!WARNING]
> Ennen kuin kokeilet siirtyä graaafisesta työpöytäympäristöstä tekstimuotoiseen TTY-ympäristöön, kannattaa tarkistaa komennolla ` $ who↵ ` graafisen ympäristön TTY numero, jotta osaa tarvittaessa siirtyä sinne takaisin.

<!-- EHKÄ POIS - Shell-ohjelma lukee käynnistyessään sarjan näitä runcom määritystiedostoiksi kutsuttuja skriptejä. Ensin luetaan kaikille käyttäjille yhteisen oletusympäristön määrittelevät skripti-tiedostot. Käyttäjien omissa kotihakemistoissa on lisää määritystiedostoja. Ne luetaan seuraavaksi ja ne määrittelevät käyttäjän henkilökohtaisen ympäristön.--> <!--Näiden ensimmäisellä rivillä kerrotaan yleensä millä tulkilla ne on tulkittava ja tulkiksi määritellään yleensä /bin/sh, jonka on oltava olemassa.-->

#### Määritystiedostojen sijainti

Kaikille käyttäjille yhteiset määritystiedostot sijaitsevat hakemistossa ` /etc/ `, joko suoraan tai ohjelman mukaan nimetyssä alikansiossa.

Käyttäjäkohtaiset määritystiedostot sijaisevat <ins>käyttäjän kotihakemistossa</ins> a) hakemiston ylätasolla piilotiedostona, b) ohjelman mukaan nimetyssä piilohakemistossa, tai c) yhteiskäyttöisessä piilohakemistossa **` ~/.config/ `**.

> [!NOTE]
> Piilotiedosto on oletusarvoisesti näkymätön hakemistoluettelointi- ja tiedostonhallintatyökaluille mikä vähentää visuaalista kaaosta. Tällaisia tiedostoja kutsutaan usein **pistetiedostoiksi** (englanniksi **dotfiles**), koska unixeissa piste ` . ` tiedoston nimen alussa tekee siitä piilotiedoston. 

#### Bash määritystiedostot

Bash-istunnon konfiguraatiotiedostojen määrä ja lukujärjestys voi vaikuttaa epäjohdonmukaiselta (katso [Wikipedia - Unix shell configuration files](https://en.wikipedia.org/wiki/Unix_shell#Configuration_files)). Jos yhtä tiedostoa ei löydy, komentotulkki yrittää lukea toista, mutta ei välttämättä kaikkia. Myös GNU/Linux jakelujen välillä on eroja, eikä vain komentotulkkiversioiden välillä.

Uusille käyttäjille riittänee pitäytyminen, nykyaikaisten GNU/Linux jakeluiden, kahdessa tärkeimmässä käynnistystiedostossa:
1. Tärkein <ins>järjestelmänlaajuinen</ins> käynnistystiedosto **` /etc/profile `** koskee kaikkia alkuperäisen Bourne Shellin (sh) tai minkä tahansa Bourne-yhteensopivan shellin (kuten bash, zsh, ksh, ash) käyttäjiä.
2. Tärkein <ins>käyttäjäkohtainen</ins> käynnistystiedosto on **` ~/.bashrc `**, joskin vain Bourne Again Shellille (bash).

> [!HUOM!]
> Pääkäyttäjän tärkein bash-määritystiedosto löytyy pääkäyttäjän kotihakemistosta ` /root/.bashrc `.

<a id="environment-variables"></a>

### Ympäristömuuttujat <!--update internal links if changed-->

**Muuttuja** (englanniksi **variable**) tarkoittaa nimettyä tietovarastoa, josta tietoa voidaan hakea ja johon tietoa voidaan kirjoittaa. Unix-ympäristössä on joukko ympäristömuuttujiin taltioituja asetuksia, joiden tarkoitus on olla yhteisiä kaikille ohjelmille.

Unix-**ympäristömuuttujat** (englanniksi **environment variables**) ovat <ins>nimi-arvo-pareja</ins>, joissa nimet ja arvot ovat molemmat tyypiltään merkkijonoja (englanniksi string). Unix-ympäristömuuttujien nimeämiskäytäntö koostuu isoista kirjaimista, numeroista ja alaviivasta (_). 

Unix-ympäristömuuttujat periytyvät siten, että uusi käynnistettävä ohjelma saa käynnistävän ohjelman ympäristömuuttujat. Muutokset ympäristömuuttujiin vaikuttaa vain siihen ympäristöön, jossa muutos tehtiin, sekä sen alta käynnistettyihin ohjelmiin.

Ympäristömuuttujat eivät ole sovelluskohtaisia, vaan <ins>jaetaan useiden ohjelmien kesken</ins>. Yhteistä ympäristömuuttujille on se, että olisi ärsyttävää kopioida niiden sisältämät identtiset tiedot monien sovellusten ohjaustietoihin. Ja erittäin ärsyttävää olisi muuttaa näitä tietoja kaikkialla, kun asetukset muuttuvat.

> [!TIP]
> Kaikkien ympäristömuuttujien sisällön saa näkyviin komennolla ` $ printenv↵ `.
>
> Yksittäisen ympäristömuuttujan sisällön voi tarkistaa komennolla ` $ echo $MUUTTUJAN_NIMI↵ `.
>
> Yleensä käyttäjä asettaa ympäristömuuttujat ` ~/.bashrc ` runcom-tiedostossa, jos tällaiselle on tarvetta.

<!-- 
> [!CAUTION]
> On yksi perinteinen unix-suunnittelumalli, jota emme suosittele uusille ohjelmille. Joskus käyttäjän asettamia ympäristömuuttujia käytetään kevyenä korvikkeena ohjelman mieltymysten ilmaisemiseen suorituksenohjaustiedostossa. Esimerkiksi vuonna 1987 esitellyssä kunnianarvoisassa [NetHack](https://www.nethack.org) luolastoryömintäpelissä käytettiin ` NETHACKOPTIONS `-ympäristömuuttujaa käyttäjän asetuksia varten. Tämä oli vanhan koulukunnan tekniikka. Nykyaikaisessa käytännössähän ne analysoidaan ` .nethack `- tai ` .nethackrc `-tiedostosta.
-->

<a id="well-known-variables"></a>

#### Esimerkkejä ympäristömuuttujista

| Muuttuja | Käyttötarkoitus |
|:--- |:--- |
| ` USER ` | Sisään kirjautuneen käyttäjänimi (BSD konvention mukaisesti). |
| ` LOGNAME ` | Sisään kirjautuneen käyttäjänimi (POSIX standardin mukaisesti). |
| ` HOME ` | Polku sisään kirjautuneen käyttäjän kotihakemistoon. Tämä muuttuja on erityisen tärkeä, koska monet ohjelmat tarvitsevat sitä löytääkseen käyttäjäkohtaiset määritystiedostot. |
| ` COLUMNS ` | Pääte-ikkunan leveys (mittayksikkönä merkkien kappalemäärä). |
| ` LINES ` | Pääte-ikkunan korkeus (mittayksikkönä merkkien kappalemäärä). |
| ` SHELL ` | Ensisijaisen shell-ohjelman tiedostopolku. Sovellukset käyttävät tätä aliohjelmien käynnistämiseen. |
| ` PATH ` | Luettelo hakemistoista, jotka komentotulkki tutkii etsiessään nimeä vastaavia suoritettavia komentoja. (katso [Kappale: Sovellusohjelmat](#sovellusohjelmat)). |
| ` TERM ` | Terminaali-istunnon tyyppi kuten ` xterm ` graafisessa työpöytäympäristössä, ` linux ` TTY-virtuaalikonsolissa (` Ctrl + Alt + F# `) tai vuoden 1978 pääte-emulaattori [vt100](https://fi.wikipedia.org/wiki/VT100). ` TERM ` on erityinen siinä mielessä, että ohjelmien, jotka luovat etäistuntoja verkon kautta (kuten Telnet ja ssh), odotetaan välittävän sen läpi ja asettavan sen etäistuntoon. |
| ` EDITOR ` | Ensisijaisen teksti-rivi-editorin tiedostopolku. Rivieditorin pitäisi pystyä toimimaan ilman ”kehittyneiden” päätelaitteiden toimintoja (kuten vanha ` $ ed ` tai ` $ vi `:n ex-tila). Mutta itse asiassa useimmat unix-ohjelmat tarkistavat ensin muuttujan ` VISUAL `, ja vain jos sitä ei ole asetettu, ne kysyvät ` EDITOR `:ia, jota voidaan pitää jäänteenä ajoilta, jolloin ihmisillä oli erilaiset mieltymykset rivipainotteisten ja visuaalisten editorien suhteen. |
| ` VISUAL ` | Visuaalinen tekstieditori voi olla koko näytön editori kuten ` $ nano `. Jos kutsut editoria komentoriviltä pikanäppäimin ` Ctrl + X, Ctrl + E `, niin bash kokeilee ensin ` VISUAALISTA ` editoria, ja vasta siinä epäonnistuessaan rivi-` EDITORIA `. Nykyään voit jättää muuttujan ` EDITOR ` asettamatta, tai asettaa sen samaksi muuttuja ` VISUAL ` kanssa ajamalla käskyt ` $ export EDITOR="$VISUAL"↵ ` tai ` $ export VISUAL="/usr/bin/nano"↵ `. |

> [!NOTE]
> Kun ympäristömuuttujaan on sisällettävä useita kenttiä (kuten ` PATH `), käytetään erottimena kaksoispistettä ` : `. Varsinkin kun kentät voidaan tulkita jonkinlaisiksi tiedosto- ja hakemistopoluiksi. <!--Huomaa, että jotkin komentosuorittimet (erityisesti bash ja ksh) tulkitsevat ympäristömuuttujan kaksoispisteellä erotetut kentät aina tiedostonimiksi, mikä tarkoittaa erityisesti, että ne laajenevat.-->

<a id="io-after-startup"></a>

## 2.6 Tiedon siirto ja signalointi käynnistyksen jälkeen [^raymond]

Käynnistyksen jälkeen ohjelmat saavat yleensä syöte dataa tai komentoja
1. [Keskeytyksinä standardivirran vakiosyötteessä](06-inter.md#standardivirrat) (englanniksi standard input).
1. [Prosessien välisen tiedonsiirtoväylän](06-inter.md#vastakkeet-englanniksi-sockets) kuten [D-Bus-väylän](06-inter.md#d-bus-free-bus) kautta.
1. [Jaetuissa väliaikaistiedostoissa](06-inter.md#yksinkertaiset-ipc-tekniikat-raymond) kuten ennalta tunnettu, ohjelmalle välitetty tai ohjelman päättelemä tiedostopolku.

Ohjelmat voivat antaa tuloksia kaikilla samoilla tavoilla: tiedostoihin, tiedonsiirtoväylän kautta ja standardivirran vakiolähtönä (englanniksi standard output). Nämä useat kilpailevat siirräntämekanismit ovat kaikki yhä elossa syystä, koska ne on optimoitu eri tilanteisiin.

> Kun ohjelma päättyy, se jättää jälkeensä numerokoodin, jonka avulla ohjelma ilmoittaa ajon aikana sattuneista virhetilanteista. Tämä **lopetuskoodi** (englanniksi **exit status**) on kokonaisluku väliltä 0...255. <ins>Nolla tarkoittaa ohjelman päättyneen normaalisti</ins> ja <ins>mikä tahansa muu arvo tarkoittaa epäonnistumista</ins>. Osa ohjelmista ja komennoista poistuu epäonnistuessaan aina yksinkertaisesti arvolla yksi. Osa taas käyttää eri arvoja virheen yksilöimiseksi. Man-sivuilta voi löytää kappaleen *EXIT STATUS*, jossa kuvataan mitä koodeja käytetään. Nolla tarkoittaa kuitenkin aina onnistumista. [^shotts] Katso lisää [Luku 6, Kappale: Paluuarvo](06-inter.md#paluuarvo-shotts).

[^shotts]: [William Shotts - The Linux Command Line, updated 2019](http://linuxcommand.org/tlcl.php)

<a id="design-tropes-of-unix"></a>

## 2.7 Tärkeät toistuvat teemat unix-sovelluksissa [^raymond]

Alkuperäisessä Unix-versiossa 1960-luvulla oli useita suunnittelun piirteitä, jotka ovat tärkeitä vielä nykyäänkin:

### Modulaarisuus

**Järjestelmän pilkkominen itsenäisiin komponentteihin:** Pienet, modulaariset ohjelmat, jotka tekevät yhden asian ja hyvin. Moduuleista saadaan vankkoja, koska niitä voidaan debugata ja parantaa erikseen. Yksinkertaisia ohjelmia, jotka tekevät yhden asian, voidaan yhdistää eri tavoin monimutkaisempien asioiden aikaan saamiseksi. Käytänkö kannustaa rakentamaan lisäkomponentin, sen sijaan että vanhaa ohjelmaa monimutkaistaa uusilla ominaisuuksilla.

**Esi- ja jälkikäsittelijöiden kytkennän mahdollisuus (englanniksi pre- and post-processing):** Unix ohjelmistokehitysperinteessä on aina pyritty tietoisesti olemaan rajaamatta ohjelmien kohderyhmää ja käyttömahdollisuuksia. Tällaisessa ohjelmistokehityksessä mahdollistetaan jokaisen ohjelman tulosteesta (englanniksi output) tulevan toisen, vielä toistaiseksi tuntemattoman ohjelman syöte (englanniksi input). Ohjelmoijat eivät koskaan olettaneet tietävänsä kaikkia mahdollisia käyttötarkoituksia, joihin heidän ohjelmiaan voitaisiin käyttää.

### Tekstimuotoisuus

**Kaikki työkalut kommunikoivat keskenään tekstimuotoisesti:** Ne ovat helposti sekä koneen että ihmisen luettavissa ja muokattavissa. Tavallinen teksti on jo itsessään universaali käyttöliittymä. On paljon vaikeampi kytkeä ohjelmia yhteen ja vianmääritys vaikeutuu, jos ohjelmat eivät hyväksy ja lähetä yksinkertaisia tekstivirtoja, vaan binäärisiä data-formaatteja.

### Niukkasanaisuus

**Ohjelmien pitäisi olla hiljaa, jos niillä ei ole mitään mielenkiintoista tai yllättävää sanottavaa:** Yksinkertaisuus oli osittain seurausta "köyhyydestä". Sääntö *hiljaisuus on kultaa* kehittyi alun perin siksi, että Unix luotiin aikana ennen näyttöpäätteitä. Nuoremmat lukijat eivät ehkä tiedä, että aluksi päätelaitteissa näytön virkaa toimitti tulostin. Vuoden 1969 hitaasti paperille tulostavissa päätelaitteissa jokainen rivi tarpeetonta tulostetta vei käyttäjän aikaa. Tämä rajoitus on jo kauan sitten poistunut, mutta **niukkasanaisuus** <!--(eli se, että käytetään vähän sanoja, eikä useinkaan vaikuteta kohteliaalta tai ystävälliseltä)--> on säilynyt keskeisenä piirteenä unix-ohjelmien tyylissä. <!--Älköön kuitenkaan olettako, että historiallinen alkuperä määrittää nykyisen käyttökelpoisuuden. On olemassa hyviä syitä sille, että tämä ”hiljaisuuden sääntö” on kestänyt kauan hitaita telekopioita, joilla Unix syntyi.-->

Pyytämätöntä tietoa ei anneta lainkaan ja mahdollisista virheistä ei mainita standardivirran vakiolähdössä, vaan paluuarvossa (englanniksi exit code) ja standardivirran vakiovirheessä (englanniksi standard error). Aiheeseen palataan myöhemmässä luvussa (katso [Luku 6, Kappale: Standardivirrat](06-inter.md#standardivirrat) ja [Luku 6, Kappale: Paluuarvo](06-inter.md#paluuarvo-shotts)).
    
Perinteisesti unix komenriviohjelmat tulostavat viestin vain, jos jokin menee pieleen. Oletusarvoisesti komennot eivät tulosta vahvistusviestiä onnistumisen jälkeen, eivätkä näytä edistymisilmaisinta (englanniksi progress bar).
- Usein kun syötät komennon ja painat enteriä, komento suoritetaan, mutta et näe tulosta. Komento ` $ cp ` kopioi tiedostot äänettömästi ja ilmoittamatta toiminnon onnistuneen. Komento ` $ rm ` poistaa tiedostot järjestelmästä äänettömästi ja ilmoittamatta toiminnon onnistuneen.
- Jos ohjelma haluaa tukea edistymisilmaisinta tai tuottaa yksityiskohtaisia tulosteita (helpottamaan käyttäjää tai virhediagnostiikkaa), niiden tulisi olla pois käytöstä oletusarvoisesti. Käyttäjää vaaditaan itse asettamaan tällainen tila päälle komentoriviparametrilla ` -v ` tai ` --verbose `, jolloin lisätieto annetaan vakiotulosteeseen ja/tai vakiovirheeseen:

```
$ mkdir -v Aaaa↵
mkdir: created directory 'Aaaa'

$ rmdir -v Aaaa↵
rmdir: removing directory, 'Aaaa'
```

On olemassa hyviä syitä sille, että tämä hiljaisuuden sääntö on käytössä edelleen:

- Käyttäjän näyttötila on edelleen arvokasta. Tarpeettomat viestit ovat huolimatonta kaistanleveyden tuhlausta ja yksi häiriötekijä lisää näytöllä, jonka tehtävä on välittää tärkeämpiä tehtäviä.

- Unix-periaatteen mukaan ohjelman on voitava kommunikoida käyttäjän lisäksi, myös muiden ohjelmien kanssa. Jaarittelevat ohjelmat eivät yleensä pelaa hyvin yhteen muiden ohjelmien kanssa. Jos ohjelma lähettää jaarittelevia viestejä standardivirran vakiosyötteessä, niin ohjelmat jotka yrittävät tulkita tulostetta joutuvat näkemään kohtuuttomasti vaivaa viestien tulkitsemisessa tai hylkäämisessä, vaikka mikään ei menisikään pieleen.

<!-- POISTETTU KAPPALEESTA 10 ?!?!??!
Many terminal commands will print a message only if something goes wrong. Often times as you insert a command and hit enter, the command gets executed but you do not see a result. The copy command ` $ cp `will overwrite existing files silently. The ` $ rm ` command removes files from the system without confirmation. This is because the unix shell is unobtrusive and silent by design (see [Chapter 2, Section: Design tropes of unix shell utilities](02-basic.md#design-tropes-of-unix)). By default most commands will not print confirmation messages upon success. However, many commands accept the ` -v ` parameter to change this behaviour (v is hort for verbose):
-->
    
### Äänekkyys virhetilanteissa

**Unix komentoriviohjelmat epäonnistuvat äänekkäästi ja mahdollisimman pian:** Siten ongelman diagnosointi on mahdollisimman helppoa ja oikea-aikaista. Ohjelmat pyritään toki laatimaan sellaisiksi, että ne selviytyvät virheellisistä syötteistä ja suoritusvirheistä mahdollisimman sulavasti. Ja on parasta, kun ohjelmisto selviytyy odottamattomista olosuhteista mukautumalla niihin. Mutta ohjelmiston tulisi olla läpinäkyvä siinä, miten se epäonnistuu. Pahimpia vikoja ovat ne, joissa ongelma aiheuttaa hiljaa tietojen viouttumisen, joka näkyy vasta viiveellä paljon myöhemmin.

### Vahvistuspyyntöjen vähyys

Lähtökohtaisesti unix komentotulkki tottelee hiljaisesti ja huomaamattomasti, eikä tungettele. Jopa komento ` $ rm ` yksinkertaisesti poistaa tiedostot järjestelmästä äänettömästi kysymättä haluatko todella poistaa tiedostot, saati ilmoittamatta toiminnon onnistuneen. 

**Ohjelmien tulisi pyytää vahvistusta vain ja ainoastaan silloin, kun on hyvä syy:** Kuten epäillessä vastauksen olevan suurella todennäköisyydellä vahva EI! Ja tällöinkin ohjelmien tulisi tukea komentoriviparametria ` -y ` (englanniksi yes), jolla voidaan ennalta valtuuttaa mahdollisesti tuhoisia toimia. Hyvä esimerkki tästä mallista on tiedostojärjestelmän tarkistus- ja korjaustyökalu ` $ fsck `, joka muutoin oletusarvoisesti kysyisi vahvistusta, joidenkin mahdollisesti tuhoisien toimintojen kohdalla.

### Kosmeettisten yksityiskohtien vähyys

**Ohjelmien tulisi välttää tulostamasta epäolennaista tietoa vakiolähtöön:** Olet ehkä ihmetellyt, miksi komennon ` $ ls -la↵ ` tulosteessa ei ole otsikoita. Vastaus piilee taas unix-perinteessä. Unix-komentorivityökalut tyypillisesti välttävät lisäämästä epäolennaista tietoa ja uudelleen muotoilua tavoilla, jotka saattavat vaikeuttaa tulosteen jatkokäsittelyä myöhempien ohjelmien kannalta. Yleisimpiä rikkomuksia ovat kosmeettiset yksityiskohdat kuten otsikot, alatunnisteet, tyhjät rivit, reunaviivat, yhteenvedot ja tasatut sarakkeet.

<a id="textual-formats"></a>

## 2.8 Tekstiformaatti [^raymond]

Unixissa on pitkät perinteet siitä, miten tekstimuotoinen data pitäisi jäsentää. Näiden käytäntöjen mukaista tietoa on helppo hakea ja muuntaa *perinteisillä unix-työkaluilla* kuten ` $ grep `, ` $ sed `, ` $ tr ` ja ` $ cut `.

```
$ whatis grep sed tr cut↵
grep   - print lines that match patterns
sed    - stream editor for filtering and transforming text
tr     - translate or delete characters
cut    - remove sections from each line of files
```

### Yksi tietue per rivi

Yksi tietue per rivi helpottaa tietueiden poimimista tekstivirtatyökaluilla.

### Alle 80 merkkiä per rivi

Alle 80 merkkiä per rivi takaa luettavuuden tavanomaisen kokoisessa terminaali-näkymässä.

### Kaksoispiste (:) erottimena

1. <ins>Kaksoispiste ` : ` tietueen kenttien erottimena</ins> helpottaa kenttien poimimista tekstivirtatyökaluilla.
    - Hyviä esimerkkejä kaksoispiste-käytännöstä ovat ` /etc/group `, ` /etc/passwd ` ja ` /etc/shadow `.
    - Data-tiedostojen odotetaan tukevan erotinmerkin sisällyttämistä osaksi kentän arvoa kenoviiva-notaatiolla ` \: ` (englanniksi **backslash escaping**). Myöskään kenoviivaa ei voi sisällyttää osaksi kentän arvoa sellaisenaan, vaan myös tällöin käytetään kenoviivaa etuliitteenä ` \\ `. 
    - Jos useat tietueet muodostuvat yli 80 merkkiä pitkiksi, harkitse tietueen erotinriviä ` %%\n ` tai ` %\n `. Erotinrivit ovat hyödyllisiä visuaalisia rajoja tiedostoa silmäilevälle ihmiselle.

### Riippumattomuus peräkkäisten tyhjemerkkien määrästä
    
Älä salli merkitsevää eroa tyhjemerkkien (space ja tab) välille tai määrälle. Muutoin sinulla on resepti vakavaan päänvaivaan, sillä käyttäjien ja editorien whitespace- ja tabulaattoriasetukset ovat erilaiset.

### Suosi heksadesimaalijärjestelmää

Suosi heksadesimaalijärjestelmää (kantaluku 16) ja vältä oktaalijärjestelmää (kantaluku 8). Heksanumeroparit on helpompi silmäillä tavuiksi, koska kaksi 16-kantaisen heksadesimaalijärjestelmän merkkiä vastaa suoraan yhtä tavua (eli binäärijärjestelmän kahdeksaa peräkkäistä bittiä).

### Kellon-ajat ja päivämäärät ISO8601-formaattiin

Kellon-ajat ja päivämäärät ovat erityisen hankalia, koska niitä on vaivalloista analysoida jatkojalostusohjelmilla. Kaikkien tällaisten lisäysten pitäisi olla valinnaisia ja komentoriviargumentein hallittavissa. Jos ohjelma tuottaa päivämääriä, on hyvä käytäntö ottaa käyttöön komentoriviparametri, joka pakottaa ne [ISO8601-formaattiin](https://fi.wikipedia.org/wiki/ISO_8601) **VVVV-KK-PP** ja **hh:mm:ss** tai käyttää niitä oletusarvoisesti.

### Ristikko-merkki (#) kommenttien johdantona

On hyvä tapa upottaa huomautuksia ja kommentteja myös datatiedostoihin.

### Tuki erikoismerkeille kenoviiva-notaatiolla

#### Unicode ja ASCII symbolit

Monet kielet sisältävät symboleja, joita ei ole voitu tiivistää näppäimistölle:

| Merkintä | Käyttötarkoitus |
|:--- |:--- |
| ` \u???? ` | [Unicode-merkin](https://en.wikipedia.org/wiki/List_of_Unicode_characters) lisääminen heksadesimaaliarvolla. |
| ` \x?? ` | [ASCII-merkin](https://www.ascii-code.com) lisääminen heksadesimaaliarvolla. |
| ` \??? ` | [ASCII-merkin](https://www.ascii-code.com) lisääminen oktaaliarvolla. |

```
$ printf "\u2665"↵ # Unicode HEX
♥ 

$ printf "\x40"↵   # Ascii HEX
@ 

$ printf "\100"↵   # Ascii OCT
@ 
```

#### Ohjausmerkit

Perusmerkistöön sisältyy **ohjausmerkkejä** (englanniksi **control character**), joilla ei yleensä ole näkyvää esitysmuotoa, vaan tarkoitus on käynnistää jokin laitteistoa tai tiedon käsittelyä ohjaava toimi.

| Merkintä | Käyttötarkoitus |
|:--- |:--- |
| ` \n ` | Kirjoituskohdan siirto yhden rivin verran alaspäin (englanniksi **Line Feed**). |
| ` \f ` | Kirjoituskohdan siirto seuraavalle sivulle (englanniksi **Form Feed**). | 
| ` \r ` | Kirjoituskohdan palautus ääriasentoon vasemmalle (englanniksi **Carriage Return**). |
| ` \t ` | Kirjoituskohdan siirto vaakasuunnassa seuraavaan esiasetettuun pysäytykseen (englanniksi **Horizontal Tab**). |
| ` \b ` | Askelpalautin (englanniksi **Backspace**). |
| ` \[ ` | Ohjausmerkki, joka vaihtaa terminaaliin tulostetun tekstin ominaisuuksia kuten muotoilua ja väriä (katso [Luku 7, Kappale: Komentokehotteen kustomointi](07-advanced-terminal.md#komentokehotteen-kustomointi)). |
    
> [!NOTE]
> Tietokoneella kirjoitettaessa ei tavallisesti tarvitse kiinnittää huomiota siihen, miten teksti jakautuu riveiksi. Jos teksti ei mahdu yhdelle riville, niin useimmat ohjelmistot osaavat välilyönnin jälkeen siirtää viimeisen sanan automaattisesti seuraavalle riville. Tämä ei kuitenkaan ollut itsestään selvää tekstinkäsittelyn alkuaikoina. [^kirjotuskone]

tekstinkäsittelyn alkuaikoina järjestelmää piti erikseen ohjeistaa toteuttamaan rivinvaihto, samaan tapaan kuin kirjoituskoneella piti aina rivin täyttyessä varta vasten siirtää kirjoituspää uuden rivin alkuun. Siksi ASCII-merkistöön lisättiin kaksi merkkiä. Toinen ohjasi kohdistimen rivin alkuun (englanniksi **Carriage Return**) ja toinen seuraavalle riville (englanniksi **Line feed**). [^kirjotuskone]

Vasta myöhemmin huomattiin, ettei kahta erillistä merkkiä välttämättä tarvita. Rivinvaihto saatettiin ohjelmoida tapahtumaan yhdelläkin merkillä, mutta eri järjestelmissä päädyttiin erilaisiin ratkaisuihin. Rivinvaihdon merkkinä alettiin käyttää joissain järjestelmissä pelkkää *carriage return -koodia*, ja joissain pelkkää *line feed -koodia*. Ongelmia tietysti syntyi, jos tekstitiedostoja siirrettiin järjestelmästä toiseen ja kontrollikoodikäytännöt olivat erilaiset. Mutta tämä tapahtui aikana, jolloin ei juurikaan osattu unelmoida tiedon joustavasta siirtämisestä eri ohjelmien, koneiden ja järjestelmien välillä [^kirjotuskone]

[^kirjotuskone]: [Jukka Korpela - Kirjoituskoneista tietokoneisiin, accessed 2025](https://jkorpela.fi/rv/1.1.html).

### XML

XML voi olla yksinkertaistava tai monimutkaistava valinta:
- XML on itsessään melko tilaa vievä. Tietoa voi olla vaikea nähdä kaiken merkinnän keskellä.
- XML:n vakavin ongelma on se, että se ei toimi hyvin perinteisten unix-työkalujen kanssa. Ohjelmistot, jotka haluavat lukea XML-muotoa, tarvitsevat XML-parserin. Tämä tarkoittaa tilaa vieviä, monimutkaisia ohjelmia.
- Yksi sovellusalue, jolla XML on selvästi voitolla, on asiakirjatiedostojen merkintäformaatit.
- Pakattu XML (kuten \*.docx ja \*.odt) yhdistää tilansäästön joihinkin tekstimuotoisen formaatin etuihin. Erityisesti siinä vältetään monet binääriformaatteihin liittyvät ongelmat.

<a id="binary-formats"></a>

## 2.9 Binääri-formaatit [^raymond]

### Tekstualisaattori

Aina kun kohtaat suunnittelun ongelman, johon liittyy jonkin monimutkaisen binääriobjektin muokkaaminen, unix-perinne kannustaa kysymään ensin, voitko kirjoittaa työkalun, <!--joka on analoginen ` $ sng `:n tai ` $ tic ` / ` $ infocmp `-parin kanssa ja -->joka voi tehdä <ins>häviöttömän käännöksen muokkauskelpoiseen tekstimuotoon ja siitä takaisin</ins>. Tällaisille ohjelmille ei ole vakiintunutta termiä, mutta kutsumme niitä **tekstualisaattoreiksi**.

### Selain

Jos binääriobjekti on dynaamisesti luotu tai hyvin suuri, ei ole käytännöllistä tai välttämättä edes mahdollista muuntaa kaikkea tekstualisaattorilla. Tällöin vastaava tehtävä on kirjoittaa **selain** (englanniksi **browser**). <!--Esimerkkinä on ` $ fsdb `, tiedostojärjestelmän debuggeri, jota tuetaan useissa Unixeissa. Linuxissa on vastaava nimeltä ` $ debugfs `. Toinen esimerkki on ` $ psql `, jota käytetään PostgreSQL-tietokantojen selaamiseen.--> Hyviä esimerkkejä tästä mallista ovat ` $ psql `, jota käytetään PostgreSQL-tietokantojen selaamiseen, sekä ` $ fsdb `, tiedostojärjestelmän debuggeri, jota tuetaan useissa Unixeissa; Linuxissa on vastaava nimeltä ` $ debugfs `.

<!--> [!IMPORTANT]
> Älä vaivaudu pakkaamaan tai binääri-koodaamaan vain osaa tiedostosta.-->

<!-- # References -->

[^raymond]: [Eric Steven Raymond - The Art of Unix Programming, published 2003](https://www.arp242.net/the-art-of-unix-programming/)
