# NetRogue
### Autors: Rihards Bukovskis
Šis projekts būs dažādu WIFi ievainojamību apkopojums vienā rīkā. Lietotājam būs iespēja izvēlēties kādu no implementētajām ievainojamībām un to palaist, izmantojot savu tīkla karti.
Pamatā iekļautas ievainojamības: ZPD OWE uzbrukumi, PMKID, Evil Twin AP
Programma būs rakstīta C valodā, tās zemā līmeņa un augstā ātruma dēļ.

## Ierobežojumi

**Programmatūra darbojas tikai uz linux sistēmām.**

Specifiskie ierobežojumi katram uzbrukumam:

- OWE uzbrukumi:
  - Nepieciešama tīkla karte, kas atbalsta Monitor režīmu
- PMKID uzbrukums:
  - Nepieciešamas divas tīkla kartes. Vienai no tām ir jāatbalsta Monitor režīms
- Twin Ap uzbrukums:
  - Nepieciešamas divas tīkla kartes, vai viena tīkla karte un savienojums ar internetu caur ethernet kabeli


## Programmatūras instalēšana

#### Klonē repozitoriju
```
git clone https://github.com/rihrds/NetRogue.git
cd NetRogue
```
#### Programmas izveide/kompilēšana
```
make
```
#### Programmas palaišana
```
./netrogue
```
Piezīme: Programmai ir nepieciešamas root privilēģijas, tāpēc, ja lietotājs, kas palaiž programmu nav root, tad tā jāpalaiž ar sudo:
```
sudo ./netrogue
```
