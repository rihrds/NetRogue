# NetRogue
### Autors: Rihards Bukovskis
Šis projekts būs dažādu WIFi ievainojamību apkopojums vienā rīkā. Lietotājam būs iespēja izvēlēties kādu no implementētajām ievainojamībām un to palaist, izmantojot savu tīkla karti.
Pamatā iekļautas ievainojamības: OWE, PMKID, Evil Twin AP + SSID stripping
Programma būs rakstīta C valodā, tās zemā līmeņa un augstā ātruma dēļ.

#### Ierobežojumi
Programma strādās tikai uz linux ierīcēm, jo linux piedāvā visērtāko pieeju zemajam tīkla līmenim, kamēr ar windows to izdarīt ir daudz sarežģītāk, un tikai ar tīkla kartēm, kuras ir iespējams ielikt Monitor mode, jo tikai tā var noklausīt visu tīkla satiksmi.
