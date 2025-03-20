<p style="font-size:20px; "> Nume: Pogan Alexandru-Mihail </p>
<p style="font-size:20px; "> Grupa: 335CA </p>
<p style="font-size:20px; "> Cerinte rezolvate: 1 2 3 </p>

# Tema 1 - Implementare Switch (0.8p)

<p style="font-size:20px; text-indent: 30px; "> In cadrul acestei teme, se cere implementarea unui switch virtual, care in contextul unei retele generate cu ajutorul utilitarului Mininet, trebuie sa gestioneze pachetele pe care le primeste din partea celorlalte dispozitive din retea, inclusiv alte switch-uri, exact ca un switch real. </p>
<p style="font-size:20px; text-indent: 30px; "> In acest scop, tema prezinta trei mari parti:

1. <p style="font-size:20px; text-indent: 30px; ">Implementarea mecanismului de comutare a frame-urilor </p>
2. <p style="font-size:20px; text-indent: 30px; "> Adaugarea conceptului de VLAN. </p>
3. <p style="font-size:20px; text-indent: 30px; "> Implementarea algoritmului Spanning Tree Protocol simplificat. </p>

<p style="font-size:20px; text-indent: 30px; "> Inainte de implementarea propriu-zisa, am ales sa folosesc doua structuri foarte importante pentru rezolvarea temei, si anume <strong>SwitchStructure</strong>, reprezentarea pentru switch-ul din problema, precum si clasa BPDU, reprezentarea mesajelor transmise pe parcursul desfasurarii algoritmului Spanning Tree Protocol. Reprezentarea lor in cod o gasiti mai jos:

```python 

class SwitchStructure:
    def __init__(self, priority, interfaces, source_mac):
        self.priority = priority
        self.interfaces = interfaces
        self.interface_dictionary = {}          # the structure containing the plain information from the configuration files
        self.interface_types = {}               # structure handling interface types
        self.interface_vlans = {}               # structure handling vlans
        self.port_states = {}                   # structure handling states(listening/blocking)
        self.root_port = 0                  
        self.source_mac = source_mac        
        self.bpdu = None                        # switch's bpdu
        
        # own_bridge_ID  is switches current status  
        self.own_bridge_ID = priority

        # root_bridge_ID is equal to own_bridge_ID in the first phase
        self.root_bridge_ID = self.own_bridge_ID

        # the cost to the root bridge is clearly 0 in the first phase
        self.root_path_cost = 0

class BPDU:
    def __init__(self, source_mac, destination_mac, DSAP, SSAP, control, flags, root_bridge_id, root_path_cost, bridge_id, port_id, message_age, max_age, hello_time, forward_delay):
        self.source_mac = source_mac
        self.destination_mac = destination_mac
        self.DSAP = DSAP
        self.SSAP = SSAP
        self.control = control
        self.root_bridge_id = root_bridge_id
        self.root_path_cost = root_path_cost
        self.own_bridge_id = bridge_id
        self.port_id = port_id
        self.flags = flags
        self.message_age = message_age
        self.max_age = max_age
        self.hello_time = hello_time
        self.forward_delay = forward_delay 
```

<p style="font-size:20px; text-indent: 30px; "> Pentru clasa switch-ului, am definit o serie de structuri de interes:

1. <p style="font-size:20px; text-indent: 30px; ">self.interface_dictionary --> structura in care adaug toate datele din fisier, indiferent de tipul portului </p>
2. <p style="font-size:20px; text-indent: 30px; ">self.interface_types --> structura care continue tipul interfetelor switch-ului </p>
3. <p style="font-size:20px; text-indent: 30px; ">self.interface_vlans --> structura care contine vlanurile fiecarei interfete(sau 0 pentru interfetele trunk) </p>
4. <p style="font-size:20px; text-indent: 30px; ">self.port_states --> structura cu statusurile interfetelor(utila la cerinta cu stp) </p>

<p style="font-size:20px; text-indent: 30px; "> Am mai definit un dictionar pentru stocarea legaturilor mac->interfata </p>
<br>

# Implementarea cerintelor

1. <p style="font-size:20px; text-indent: 30px; "> In bucla infinita, adaug in mac_table legatura src_mac -> interfata de pe care au venit datele noi, urmand sa verific daca mac-ul destinatie este destinatie. Daca am intrare in mac table pentru mac-ul destinatie, trimit datele pe interfata aferenta din structura. In caz contrar, trimit datele prin toate interfetele switch-ului, mai putin interfata de unde a sosit frame-ul, exact ca la broadcast/multicast. </p>

2. <p style="font-size:20px; text-indent: 30px; "> Pentru implementarea VLAN-ului, citesc datele din fisierul de configuratii aferent switch-ului, urmand ca in functia send_frame, sa verific tipul legaturii curente intre interfata de sosire, respectiv cea destinatie. In cod, am tratat toate cele patru cazuri posibile. Daca avem legatura access to trunk, adaugam vlan tagul la datele primite. Daca urmatoarea interfata este tip trunk, trimitem datele fara sa tinem cont de vlan. Daca avem destinatie access, verificam daca vlan_id == vlan_ul interfetei destinatie. Pentru legatura access to access, cum vlan_id-ul initial este -1, il modific corespunzator cu vlan-ul calculatorului sursa. </p> 

3. <p style="font-size:20px; text-indent: 30px; "> Pentru implementarea algoritmului, prima data initializam fiecare switch cu parametrii necesari desfasurarii algoritmului. Practic, fiecare switch se declara ca root-bridge, cu costul total initial fiind nul. De asemenea, ma sigur ca toate interfetele tip trunk sunt in starea "blocking". Dupa, fiecare switch trimite cate un hello bpdu, pentru a descoperi topologia si ceilalti vecini. Pentru asta, imi definesc un obiect nou tip BPDU, cu parametrii cu care am initializat si switch-ul, precum si cu destinatia mac specifica frame-ului Spanning Tree Protocol, anume <strong>01:80:c2:00:00:00</strong>, obiectul urmand a fi convertit in bytes, pentru a-l trimite catre toate celelalte interfete. Daca switch-ul primeste un frame cu destinatia specifica, parsam BPDU-ul si verificam urmatoarele:
    
 <p style="font-size:20px; text-indent: 30px; "> a) Daca switch-ul a primit frame-ul de la un root bridge mai mic, actualizam costul drumului pana la el, precum si root_bridge-ul. Specificam root-portul ca interfata de sosire si modificam starea in "listening", daca e cazul. De asemenea blocam toate celelalte interfete trunk. </p>
 <p style="font-size:20px; text-indent: 30px; "> b) Daca root-bridge-urile sunt egale, modificam costul doar daca e cazul, iar interfata de sosite e root port, in caz contrar pentru distanta totala a BPDU-ului mai mare, setam toate porturile switch-ului pe "listening" (designated) </p>
 <p style="font-size:20px; text-indent: 30px; ">c) Daca own bridge-ul transmitatorului e la fel ca cel al receptorului, interfetele receptorului se blocheaza </p>

 <p style="font-size:20px; text-indent: 30px; "> Ulterior, daca switch-ul ramane root, toate porturile se fac designated, deci "listening. De asemenea, la fiecare o secunda, root bridge-ul trimite un bpdu, cu root_path_cost-ul 0. </p>

  <p style="font-size:20px; text-indent: 30px; "> Ca algoritmul sa functioneze, am modificat functia send_frame, ca datele sa fie trimise numai prin interfete designated+root(cele care se afla in starea "listening") </p>