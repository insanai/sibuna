<!-- English source SHA-256: 48d28acad3b10231e32c88bcf3d43e324be89f143fe1bea1ee6492a32e5a1c0e -->
<h1 align="center">sibuna</h1>
<p align="center">Protección web con prueba de trabajo en el navegador y consola opcional.</p>
<p align="center">
  <a href="#features">Características</a> ·
  <a href="#quickstart">Inicio rápido</a> ·
  <a href="#console">Consola</a> ·
  <a href="#how-it-works">Cómo funciona</a> ·
  <a href="#documentation">Documentación</a>
</p>

<!-- language-navigation -->
<p align="center">
  <a href="README.md">English</a> · <a href="README.zh-CN.md">简体中文</a> ·
  <a href="README.ko.md">한국어</a> · <a href="README.ja.md">日本語</a> ·
  <a href="README.es.md">Español</a> · <a href="README.de.md">Deutsch</a> ·
  <a href="README.hi.md">हिन्दी</a> · <a href="README.ar.md">العربية</a>
</p>

**Sibuna ayuda a proteger sitios web y API frente a tráfico de bots no deseado.** Puede
reenviar peticiones a tu aplicación o acompañar a un proxy existente, como Caddy, nginx o Traefik.

Enviar peticiones suele ser barato. Procesarlas puede exigir más trabajo a tu aplicación.
Sibuna pide resolver un desafío antes de conceder acceso. Está diseñado para que crear
la prueba requiera más cálculo que verificarla. Los clientes automatizados asumen una
parte mayor del coste de acceder al sitio.

Calcular también consume energía, pero la cantidad depende del hardware y los ajustes.
La prueba de trabajo añade un coste de admisión. No demuestra que alguien sea humano
ni detiene todos los ataques. Una sesión firmada permite volver sin resolver un desafío
por petición. Las reglas y límites locales controlan qué se puede pedir después.

<a id="features"></a>

## Características

- **Un ejecutable:** motor, almacenamiento integrado, solucionador y activos de consola.
- **Paquetes nativos:** Linux, macOS y Windows. El solucionador usa WebAssembly.
- **Desafíos de navegador:** Hashcash o trabajo secuencial configurables y una sesión firmada.
- **Políticas de acceso:** permitir, desafiar o denegar por dirección, ruta, cabeceras y User-Agent.
- **Inspección de aplicaciones:** comprobaciones de inyección SQL, XSS y recorrido de rutas.
- **OWASP CRS opcional:** actualizaciones firmadas, Audit y Enforce, pruebas privadas y reversión.
- **Límites locales:** controlar ráfagas y tráfico sostenido, con límites opcionales por regla.
- **Consola:** tráfico, actividad de países muestreada, incidentes y edición de políticas.
- **Clústeres:** una compilación separada replica políticas y reputación mediante Zaxonlite.

<a id="quickstart"></a>

## Inicio rápido

[Descarga una versión](https://github.com/insanai/sibuna/releases/tag/v0.3.3) para tu plataforma. El paquete por defecto incluye soporte
de almacenamiento y consola. La consola arranca con `--console`.

| Plataforma | Paquete | Requisitos |
| --- | --- | --- |
| Linux x86-64 | `sibuna-linux-amd64.tar.gz` | Linux 5.10 o posterior; musl enlazado estáticamente |
| Linux ARM64 | `sibuna-linux-arm64.tar.gz` | Linux 5.10 o posterior; musl enlazado estáticamente |
| macOS Apple Silicon | `sibuna-macos-arm64.tar.gz` | macOS 15 o posterior |
| macOS Intel | `sibuna-macos-amd64.tar.gz` | macOS 15 o posterior |
| Windows x86-64 | `sibuna-windows-amd64.zip` | Windows 10 / Server 2019 o posterior; `sibuna.exe` nativo |

Los paquetes macOS no están firmados. Cada paquete incluye licencias, enlaces a fuentes
y manifiesto. Verifica el archivo contra `SHA256SUMS` antes de usarlo.

Para Linux x86-64, con la aplicación escuchando en el puerto 3000:

```sh
curl -fLO https://github.com/insanai/sibuna/releases/download/v0.3.3/sibuna-linux-amd64.tar.gz
curl -fLO https://github.com/insanai/sibuna/releases/download/v0.3.3/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf sibuna-linux-amd64.tar.gz
(umask 077; openssl rand -hex 32 > sibuna.seed)
./sibuna --host 127.0.0.1 --port 8080 --upstream-port 3000 --secret-file ./sibuna.seed
```

Abre `http://127.0.0.1:8080` para probarlo localmente. En un sitio público, termina HTTPS en un proxy de
entrada fiable y mantén privado el listener de Sibuna. Sigue la [guía de despliegue](https://insanai.github.io/sibuna/es/book/operations.html)
para Caddy o nginx.

El modo por defecto es `reverse_proxy`. Usa `--mode forward_auth` si el proxy de entrada reenvía peticiones y consulta
la decisión de acceso. La guía incluye ambas configuraciones. La inspección integrada
Shield está activa por defecto. Usa `--gate` para admisión sin ese inspector. Elige reglas con
`--policy-file <file>`, incluidas reglas para API y comprobaciones de salud que no pueden resolver desafíos.

En Windows, extrae el ZIP y ejecuta `.\sibuna.exe --help` en PowerShell. Detén con Ctrl+C. Restringe
archivos de semilla, credenciales y datos con ACL de Windows.

<a id="build-from-source"></a>

### Compilar desde las fuentes

Usa **Zig 0.17.0**. El repositorio contiene sumas de la cadena de herramientas y dependencias fijadas.

```sh
git clone git@github.com:insanai/sibuna.git
cd sibuna
python3 tools/prepare_build.py
zig build -Doptimize=safe -j2
```

El ejecutable es `zig-out/bin/sibuna`. Compilar clúster usa `-Dcluster=true` y necesita OpenSSL 3. Consulta
[CONTRIBUTING.md](CONTRIBUTING.md), en inglés, para las comprobaciones.

<a id="enable-owasp-crs"></a>

### Activar OWASP CRS

CRS está desactivado por defecto. Descarga y verifica una versión firmada compatible.
Empieza en Audit para revisar hallazgos sin aplicar denegaciones CRS:

```sh
./sibuna crs check --version 4.30.0 --output ./crs-candidate
./sibuna --host 127.0.0.1 --upstream-port 3000 --secret-file ./sibuna.seed \
  --crs-mode audit --crs-dir ./crs-candidate
```

Usa un directorio de candidato nuevo. Comprobarlo no cambia el daemon activo. CLI y
consola pueden preparar actualizaciones, revisar y seleccionar un candidato verificado.
Activa Enforce tras probar tráfico normal y revisar exclusiones. La [guía CRS](https://insanai.github.io/sibuna/es/book/operations.html)
explica actualizaciones, reversión, límites e inspección incompleta. Forward-auth exige
`--crs-profile headers` y no ve los cuerpos completos de la aplicación.

<a id="console"></a>

## Consola

La consola usa el mismo ejecutable. Inicializa un administrador con el daemon detenido:

```sh
./sibuna init-admin admin --data-dir ./data
./sibuna --host 127.0.0.1 --upstream-port 3000 --secret-file ./sibuna.seed \
  --data-dir ./data --console 127.0.0.1:19446
```

Abre `http://127.0.0.1:19446/console/` y cambia la contraseña temporal. La [guía de operaciones](https://insanai.github.io/sibuna/es/book/operations.html) explica HTTPS,
importaciones GeoIP y actualizaciones CRS. Añade las opciones CRS del ejemplo anterior
para activar inspección junto a la consola.

![Globo de consola Sibuna, cronología de peticiones y cobertura](docs/readme/images/console-globe.jpg)

El globo muestra actividad muestreada por país durante el último minuto. Los marcadores
son posiciones aproximadas. Las flechas apuntan al servidor configurado, no muestran
conexiones individuales en vivo. GeoIP necesita importar datos aparte. Usa `--console-location <latitude,longitude>` para
situar el servidor.

<details>
<summary>Tráfico, editor de políticas e investigación de incidentes</summary>

**Resumen de tráfico** — resultados de peticiones, ventanas observadas y actualizaciones en vivo.

![Consola Sibuna: contadores de peticiones admitidas, desafiadas y denegadas](docs/readme/images/console-dashboard.jpg)

**Editor de políticas** — ejemplo de desafío en checkout con criterios y ajustes explícitos.

![Editor de Sibuna con un borrador de regla de desafío para checkout](docs/readme/images/console-policy-editor.jpg)

**Investigación de incidentes** — evidencia y cabeceras de petición acotadas y redactadas.

![Evidencia de incidente con cabeceras redactadas y estado de respuesta](docs/readme/images/console-incident.jpg)

</details>

Son capturas Chrome de v0.2.0 en un nodo de revisión. Tráfico y GeoIP son datos de prueba.
Los contadores no son resultados de rendimiento.

<a id="how-it-works"></a>

## Cómo funciona

Una petición puede admitirse, desafiarse o denegarse. Quien resuelve obtiene una sesión
firmada. Las peticiones posteriores siguen pasando reglas y límites aplicables.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/admission-session-dark.svg">
  <img src="docs/readme/images/admission-session.svg" alt="Resolver un desafío, recibir una sesión firmada y comprobar reglas después">
</picture>

Gate comprueba reglas, sesiones y límites locales. Shield añade el inspector integrado.
CRS nativo se configura aparte. Empieza en Audit antes de activar Enforce.

<details>
<summary>Gate, Shield y los módulos de Sibuna</summary>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/protection-surfaces-dark.svg">
  <img src="docs/readme/images/protection-surfaces.svg" alt="Decisiones Gate y Shield: permitir, desafiar o bloquear">
</picture>

El diagrama muestra controles integrados Gate y Shield. CRS opcional añade inspección
propia. Una sesión válida no evita comprobaciones de ataques ni límites aplicables.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/subsystems-dark.svg">
  <img src="docs/readme/images/subsystems.svg" alt="Responsabilidades de los módulos de Sibuna">
</picture>

Los módulos separan red, pruebas, políticas, estado local y gestión.
El [libro](https://insanai.github.io/sibuna/es/book/) explica sus responsabilidades.

</details>

<a id="deployment-limits"></a>

### Límites de despliegue

Sibuna usa HTTP/1.1 en su listener privado. El proxy de entrada maneja TLS y HTTP/2
públicos. Forward-auth inspecciona metadatos recibidos. La inspección CRS completa en
proxy inverso usa límites de cuerpo y trabajo. El inspector integrado cubre 8 KiB
iniciales. Sin CRS, las subidas fluyen. Los mensajes WebSocket se retransmiten sin
inspección. CRS completo limita por defecto peticiones a 4 MiB y respuestas a 1 MiB,
y guarda cuerpos para inspeccionar. Enforce rechaza inspección incompleta. Revisa límites
y excepciones de flujo para tu aplicación antes de activarlo.

Los límites son locales a cada nodo. Sibuna no mitiga ataques volumétricos de red.
El objetivo estricto de rendimiento de consola no ha pasado formalmente. Revisa
[límites y mediciones](https://insanai.github.io/sibuna/es/book/operations.html) antes de activarla junto a una aplicación de producción.

<a id="benchmarks"></a>

## Pruebas de rendimiento

El libro registra revisión, configuración y servidor de cada prueba. Estas mediciones
muestran coste por petición con una carga; no protección equivalente ni precisión de bots.

<a id="three-product-comparison"></a>

### Comparación de tres productos

Se compararon **Sibuna v0.2.0**, Anubis 1.27.0 y BunkerWeb 1.6.15 el 4 de octubre de 2026.
Servidor y generador estaban en hosts físicos separados. Cada producto usó cuatro CPU,
64 conexiones y el mismo origen Caddy. Desafíos y gestión estaban inactivos. Son medianas
de cinco pruebas.

| Perfil | GET benigno (req/s) | p99 (ms) | POST JSON de 8 KiB (req/s) | p99 (ms) |
| --- | ---: | ---: | ---: | ---: |
| Origen directo | 70,759 | 4.67 | 13,719 | 9.01 |
| Sibuna Gate | 71,270 | 4.12 | 13,719 | 9.16 |
| Anubis | 28,277 | 7.50 | 13,718 | 9.20 |
| BunkerWeb, CRS desactivado | 13,617 | 8.27 | 12,300 | 8.94 |
| Sibuna Shield | 70,909 | 4.06 | 13,719 | 9.08 |
| BunkerWeb, CRS activado | 2,730 | 32.73 | 797 | 98.42 |

El perfil CRS de BunkerWeb inspecciona más que Shield v0.2.0 en esta tabla. Sibuna v0.3.0
añade CRS nativo y es posterior a esta comparación. Ambos hosts son contenedores
compartidos. No se controlaron frecuencia CPU ni actividad ajena.

<a id="native-crs-in-v030"></a>

### CRS nativo en v0.3.0

Esta prueba separada usó ocho paneles, cuatro CPU y 16 conexiones desde otro host.
Son tasas medianas de cinco rondas. El inspector integrado estaba desactivado.

| Carga | CRS desactivado (req/s) | Audit, paranoia 1 (req/s) | Audit, paranoia 2 (req/s) |
| --- | ---: | ---: | ---: |
| GET pequeño | 47,311 | 10,787 | 7,423 |
| POST JSON de 8 KiB | 13,726 | 1,151 | 799 |
| Subida multipart de 16 KiB | 6,704 | 4,248 | 2,887 |

En paranoia uno, p99 fue 2.34 ms, 23.43 ms y 6.34 ms para estas cargas. El RSS máximo
fue 133.8–140.5 MiB entre perfiles CRS. Ninguna petición alcanzó el límite de trabajo.
Se usó revisión limpia `d461e7f`. Contenido y concurrencia difieren de la comparación de tres
productos; estas tablas no forman una comparación equivalente.

Consulta los [registros de rendimiento](benchmarks/results/README.md) para rangos, CPU, memoria, Enforce y comandos
reproducibles. Estas cifras no pasan la prueba separada console-impact.

<a id="documentation"></a>

## Documentación

- [Libro](https://insanai.github.io/sibuna/es/book/): conceptos, algoritmos, ejemplos y mediciones.
- [Whitepaper, en inglés](https://insanai.github.io/sibuna/whitepaper/): arquitectura, pruebas y diseño.
- [Guía de operaciones](https://insanai.github.io/sibuna/es/book/operations.html): instalación y despliegue.
- [Referencia](https://insanai.github.io/sibuna/es/book/reference.html): CLI y protocolo.
- [Debates de diseño, en inglés](https://insanai.github.io/sibuna/sid/): decisiones y contratos de ingeniería.
- [Contribuir, en inglés](CONTRIBUTING.md): compilación y comprobaciones.

<a id="other-software-to-consider"></a>

## Otras herramientas que considerar

- [Anubis](https://github.com/TecharoHQ/anubis): desafíos de navegador para reducir rastreadores.
- [BunkerWeb](https://github.com/bunkerity/bunkerweb): nginx, ModSecurity, CRS y desafíos de bots.
- [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity): motor WAF mediante conectores.
- [Coraza](https://github.com/corazawaf/coraza): biblioteca WAF Go con reglas ModSecurity y CRS.
- [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset): reglas de detección para motores WAF.

Estos proyectos cubren partes distintas de la protección web. Sibuna evalúa versiones
firmadas de CRS estándar. Plugins, Lua y otros conjuntos ModSecurity quedan fuera del alcance.

<a id="license"></a>

## Licencia

El motor es **LGPL 3.0**. La consola y su interfaz WebAssembly son **AGPL 3.0**.
El ejecutable por defecto combina ambos y se distribuye con AGPL 3.0. Usa `-Dconsole=false` para
compilar el motor sin consola.

[LICENSE](LICENSE) explica el alcance. [LICENSES](LICENSES) contiene los términos completos.
[NOTICE](NOTICE) enumera dependencias. Fuentes y scripts están en cada etiqueta de versión.

Las empresas que busquen otros términos pueden contactar con Vikrant Rathore y Ronak
Rathore. Las bibliotecas y materiales de terceros conservan sus respectivas licencias.
