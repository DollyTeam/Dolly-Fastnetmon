# Dolly-Fastnetmon
AnttiDDOS DollyTeam - Fastnetmon &amp; Mikrtoik

/****************************************************/
            Versión MultiUpstream
/****************************************************/

Desde el equipo de DollyTeam, hemos creado un script para automatizar mediante la Api de Mikrtoik las reglas de RBTH o BlackHole,
lo que permite, descartar el trafico entrante (cuando estas siendo atacado) en el router de borde de tu Carrier. 
Evitando saturar tu router de borde, tanto por recursos como por anchos de banda.

El proceso es simple, solo tendrás que indicar tus Upstream en el scrip "mikrotik-fastnetmon.php", en concreto en la línea 13.
$provider_RBTH = 'Cogent-Ntt'; 

Una vez el demonio de Fastnetmon detecte un ataque a tu router de borde, mandara los parámetros necesarios para que el script
se ejecute y este mande los comandos necesarios al Mikrotik este su vez creará las reglas de blackhole.


            
