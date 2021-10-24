# Sigurnost računala i podataka

---

# **LAB 1 - Man-in-the-middle attacks (ARP spoofing)**

---

U prvoj laboratorijskoj vježbi pokušali smo izvesti man in the middle napad te nakraju i DoS (Denial of Service) na računala koja su spojena na LAN.

To smo radili pomoću **Dockera** na kojem smo imali 3 virtualna računala (station-1, station-2, evil-station).

Unutar Windows terminala spojili smo se na Ubuntu terminal te nakon dolaska u odgovarajući direktorij izveli smo naredbu `git clone [https://github.com/mcagalj/SRP-2021-22](https://github.com/mcagalj/SRP-2021-22)` koja kopira dani repozitorij.

Pomoću naredbe cd pozicionirali smo se u direktorij arp-spoofing u kojem su skripte **start.sh** i **stop.sh** koje pokreću i zaustavljaju docker.

Nakon toga smo **pokrenuli shell** station-1 i station-2

`$ docker exec -it station-1 bash`

`$ docker exec -it station-2 bash`

Onda smo provjerili da li se ta dva računala nalaze na istoj mreži pomoću

`$ ping station-2` sa station-1.

Kada smo to utvrdili napravili smo konekciju između ta dva stationa preko naredbe **netcat.**

Station-1 je bio server na portu 8000 `$ netcat -l -p 8000`, dok se station-2 spajao na station-1 `$ netcat station-1 8000`.

Na taj način smo mogli slati poruke između station-1 i station-2.

Kako bi izvršili napad na ta računala morali smo pokrenuti shell za evil-station i pokrenuti **arpspoof** i **tcpdump.**

Pokretanje shella → `$ docker exec -it evil-station bash`

Arpspoof → `$ arpspoof -t station-1 station-2` 

(gdje je station-1 računalo koje želimo prevariti, a evil-station će se pretvarati da je station-2)

Tcpdump → `$ tcpdump` (pomoću toga gledamo razmjenu paketa, te tako narušavamo **povjerljivost**)

Kada smo to sve pokrenuli, kada station-1 šalje poruku station-2 on traži IP od station-2 ali neće dobiti odgovor od station-2 nego će se za taj IP javiti evil-station i uzvratit će mu svoju eth adresu. Kada evil-station dobije poruku on je dalje prosljeđuje station-2. Tako smo narušili **integritet.**

Na kraju smo i u potpunosti prekinuli konekciju između station-1 i station-2 tj. napravili DoS čime smo narušili i **dostupnost.**

`echo 0 > /proc/sys/net/ipv4/ip_forward`