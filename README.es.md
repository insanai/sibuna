<!-- English source SHA-256: ba66ed3032a86cb4bc8f8d7ce341a92c86824be07ae3dad2f77a18ebb42e21c3 -->
<h1 align="center">sibuna</h1>
<p align="center">Protección web con prueba de trabajo en el navegador y una consola opcional.</p>
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
reenviar peticiones a tu aplicación o trabajar junto a un proxy existente, como Caddy o nginx.

Enviar peticiones suele ser barato. Procesarlas puede exigir más trabajo a tu aplicación.
Sibuna pide a los clientes que resuelvan un desafío antes de conceder acceso. El desafío está
diseñado para que crear la prueba cueste más cálculo que verificarla. Los clientes
automatizados asumen una parte mayor del coste de acceder a un sitio.

Calcular también consume energía, pero la cantidad depende del hardware y de los ajustes.
La prueba de trabajo añade un coste de admisión. No demuestra que un visitante sea humano ni
detiene todos los ataques. Una sesión firmada permite a los clientes admitidos volver sin
resolver un desafío nuevo en cada petición. Usa reglas de acceso y límites de tasa locales para
controlar lo que esos clientes pueden pedir después.

<a id="features"></a>

## Características

- **Un solo ejecutable:** motor, almacenamiento SQLite integrado, solucionador de navegador y activos de la consola.
- **Paquetes nativos:** Linux, macOS, Windows, FreeBSD y OpenBSD. El solucionador de navegador usa WebAssembly.
- **Desafíos de navegador:** prueba de trabajo secuencial (por defecto) o Hashcash, seguidos de una sesión firmada.
- **Políticas de acceso:** permitir, desafiar, ponderar o denegar peticiones por dirección, ruta, cabeceras y User-Agent.
- **Huellas TLS:** comparar la huella JA4 que reenvía un proxy de entrada de confianza, de forma exacta o por prefijo.
- **Inspección de aplicaciones:** comprobaciones integradas de inyección SQL, XSS, recorrido de rutas e inyección de comandos.
- **Límites de tasa locales:** controlar ráfagas y tráfico sostenido, con límites opcionales por regla.
- **Consola de operador:** tráfico, actividad de países muestreada, incidentes registrados y edición de políticas.
- **Soporte de clúster:** una compilación separada comparte políticas y reputación mediante PostgreSQL.

<a id="quickstart"></a>

## Inicio rápido

[Descarga una versión](https://github.com/insanai/sibuna/releases/tag/v1.0.0-beta.2) para tu
plataforma. El paquete por defecto incluye soporte de almacenamiento y consola. La consola
arranca con `--console`.

| Plataforma | Paquete | Requisitos |
| --- | --- | --- |
| Linux x86-64 | `sibuna-linux-amd64.tar.gz` | Linux 5.10 o posterior; musl enlazado estáticamente |
| Linux ARM64 | `sibuna-linux-arm64.tar.gz` | Linux 5.10 o posterior; musl enlazado estáticamente |
| macOS Apple Silicon | `sibuna-macos-arm64.tar.gz` | macOS 15 o posterior |
| macOS Intel | `sibuna-macos-amd64.tar.gz` | macOS 15 o posterior |
| Windows x86-64 | `sibuna-windows-amd64.zip` | Windows 10 / Server 2019 o posterior; `sibuna.exe` nativo |
| FreeBSD x86-64 | `sibuna-1.0.0-beta.2-freebsd-15.1-amd64.pkg` | FreeBSD 15.1; paquete CLI |
| OpenBSD x86-64 | `sibuna-1.0.0-beta.2.tgz` | OpenBSD 7.9; paquete CLI |

Esta es una versión beta. Las compilaciones para macOS no están firmadas. Cada paquete incluye
licencias, enlaces a las fuentes y un manifiesto de compilación. Verifica el archivo contra
`SHA256SUMS` antes de usarlo.

Los paquetes Debian/RPM cubren Linux x86-64 y ARM64; Arch `sibuna-bin` cubre x86-64.
Los paquetes de FreeBSD 15.1 y OpenBSD 7.9 cubren x86-64 e instalan la CLI.
Los paquetes de Linux incluyen un servicio systemd opcional y desactivado. Los paquetes BSD no
crean servicio, cuenta ni estado. Son descargas del proyecto; la aceptación en archivos
comunitarios es independiente. La versión también incluye un chart de Helm y una imagen de
contenedor, `ghcr.io/insanai/sibuna`.
Consulta la [guía de operaciones de paquetes](https://insanai.github.io/sibuna/book/operations.html)
para instalación, verificación, estado privado, actualizaciones y configuración de Kubernetes.

El [tap Homebrew de Sibuna](https://github.com/insanai/homebrew-sibuna) ofrece una fórmula CLI
que instala el archivo verificado de la versión para macOS y Linux (Apple Silicon, ARM64 y
x86-64). El tap sigue la versión publicada más reciente, así que ya ofrece esta beta. La
instalación no inicia ningún servicio:

```sh
brew tap insanai/sibuna
brew install insanai/sibuna/sibuna
sibuna --version
```

Para Linux x86-64, con tu aplicación escuchando en el puerto 3000:

```sh
curl -fLO https://github.com/insanai/sibuna/releases/download/v1.0.0-beta.2/sibuna-linux-amd64.tar.gz
curl -fLO https://github.com/insanai/sibuna/releases/download/v1.0.0-beta.2/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf sibuna-linux-amd64.tar.gz
(umask 077; openssl rand -hex 32 > sibuna.seed)
./sibuna --host 127.0.0.1 --port 8080 --upstream-port 3000 --secret-file ./sibuna.seed
```

Abre `http://127.0.0.1:8080` para probarlo localmente. En un sitio público, termina HTTPS en un
proxy de entrada de confianza y mantén privado el listener de Sibuna. Sigue la
[guía de despliegue](https://insanai.github.io/sibuna/book/operations.html) para Caddy o nginx.

El modo por defecto es `reverse_proxy`. Usa `--mode forward_auth` cuando tu proxy de entrada
reenvíe las peticiones y pida a Sibuna una decisión de acceso. La guía incluye ambas
configuraciones. La inspección integrada de Shield está activada por defecto. Usa `--gate` para
la admisión sin ese inspector. Elige las reglas de acceso con `--policy-file <file>`, incluidas
reglas para clientes de API y comprobaciones de salud que no pueden ejecutar un desafío de
navegador. `./sibuna --help` enumera todas las opciones.

En Windows, extrae el ZIP y ejecuta `.\sibuna.exe --help` en PowerShell.
Usa Ctrl+C para detenerlo. Restringe el acceso a los archivos de semilla, credenciales y datos
con ACL de Windows.

<a id="build-from-source"></a>

### Compilar desde las fuentes

Compilamos y probamos con **Rust 1.99**. El solucionador de navegador y la interfaz de la
consola son Rust compilado a WebAssembly; la compilación no necesita Node ni npm.

```sh
git clone https://github.com/insanai/sibuna.git
cd sibuna
rustup target add wasm32-unknown-unknown
cargo build --release -p sibuna
```

El ejecutable es `target/release/sibuna`. Guarda el estado en SQLite con `--data-dir`.
Las compilaciones de clúster usan `--features postgres-tls` y comparten una base de datos
PostgreSQL mediante `--database-url-file` y `--cluster-node`.
Consulta [CONTRIBUTING.md](CONTRIBUTING.md) para pruebas, lints y comprobaciones de tamaño.

<a id="console"></a>

## Consola

La consola se ejecuta en el mismo ejecutable. Inicializa un administrador con el daemon detenido:

```sh
./sibuna init-admin admin --data-dir ./data
./sibuna --host 127.0.0.1 --upstream-port 3000 --secret-file ./sibuna.seed \
  --data-dir ./data --console 127.0.0.1:19446
```

Abre `http://127.0.0.1:19446/console/` y cambia la contraseña temporal.
La [guía de operaciones](https://insanai.github.io/sibuna/book/operations.html) explica el
acceso HTTPS, las importaciones GeoIP, los usuarios, los tokens de API y las pantallas murales.

![Globo de la consola Sibuna, cronología de peticiones y cobertura](docs/readme/images/console-globe.png)

El globo muestra la actividad muestreada por país durante el último minuto. Los marcadores dan
posiciones aproximadas de los países. Las flechas apuntan hacia la ubicación configurada del
servidor. No muestran conexiones individuales en vivo. GeoIP necesita un conjunto de datos
importado por separado.
Usa `--console-location <latitude,longitude>` para situar el servidor en el globo.

<details>
<summary>Resumen de tráfico, resumen de seguridad, políticas e investigación de incidentes</summary>

**Resumen de tráfico** - resultados de peticiones, ventanas de observación y actualizaciones en vivo.

![Resumen de tráfico de la consola Sibuna con contadores de peticiones, admisiones, desafíos y denegaciones](docs/readme/images/console-traffic.png)

**Resumen de seguridad** - hallazgos registrados, desafíos, bloqueos y un flujo de eventos en vivo.

![Resumen de seguridad de la consola Sibuna con hallazgos de inspección, desafíos, bloqueos y honeypot](docs/readme/images/console-security.png)

**Políticas** - las reglas que aplica un nodo, en orden, con sus coincidencias registradas.

![Página de políticas de la consola Sibuna con la configuración aplicada y una regla de permiso](docs/readme/images/console-policies.png)

**Eventos** - incidentes registrados, con filtros por módulo, país, dirección, ruta y hora.

![Página de eventos de la consola Sibuna con filtros de incidentes y hallazgos de inyección SQL registrados](docs/readme/images/console-events.png)

</details>

Son capturas de Chromium sin interfaz gráfica de v1.0.0-beta.1 en un nodo de prueba local. El
tráfico y las asignaciones GeoIP son datos de prueba. Los contadores mostrados no son
resultados de pruebas de rendimiento.

<a id="how-it-works"></a>

## Cómo funciona

Una petición puede admitirse, desafiarse o denegarse. Un visitante que resuelve un desafío
recibe una sesión firmada. Las peticiones posteriores siguen pasando las comprobaciones de
políticas y de tasa aplicables.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/admission-session-dark.svg">
  <img src="docs/readme/images/admission-session.svg" alt="Resolver un desafío, recibir una sesión firmada y comprobar reglas en peticiones posteriores">
</picture>

Gate comprueba reglas de acceso, sesiones y límites de tasa locales. Shield añade el inspector
de ataques integrado. Shield es la opción por defecto; `--gate` selecciona Gate al arrancar.

<details>
<summary>Gate, Shield y los crates de Sibuna</summary>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/protection-surfaces-dark.svg">
  <img src="docs/readme/images/protection-surfaces.svg" alt="Decisiones de Gate y Shield sobre peticiones: permitir, desafiar o bloquear">
</picture>

El diagrama muestra las comprobaciones integradas de Gate y Shield.
Una sesión válida no evita las comprobaciones de ataques ni los límites de peticiones aplicables.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/subsystems-dark.svg">
  <img src="docs/readme/images/subsystems.svg" alt="Las tareas de los crates de Sibuna">
</picture>

Los crates separan red, pruebas, políticas, estado local, almacenamiento y gestión.
El [libro](https://insanai.github.io/sibuna/book/) explica sus responsabilidades.

</details>

<a id="deployment-limits"></a>

### Límites de despliegue

Sibuna usa HTTP/1.1 en su listener privado. Tu proxy de entrada gestiona TLS público y HTTP/2.
Forward-auth inspecciona los metadatos que aporta el proxy de entrada. En modo proxy inverso, el
inspector integrado cubre los primeros 8 KiB de un cuerpo. Las subidas fluyen hacia tu aplicación.
Los mensajes WebSocket se retransmiten sin inspección. El inspector es heurístico, no un
analizador completo del lenguaje.

Los límites de tasa son locales a cada nodo. Sibuna no ofrece mitigación volumétrica de red.
Los desafíos están ligados al nodo que los emitió; enruta un desafío y su solución al mismo
nodo. El objetivo estricto de rendimiento de la consola no ha pasado formalmente. Revisa los
[límites de despliegue y mediciones](https://insanai.github.io/sibuna/book/operations.html)
antes de activar la consola junto a una aplicación de producción.

<a id="benchmarks"></a>

## Pruebas de rendimiento

El libro registra la revisión del código fuente, la configuración y el host de cada ejecución.
Estas mediciones muestran el coste de las peticiones con algunas cargas de trabajo en una sola
máquina. No miden protección equivalente ni precisión frente a bots.

<a id="sibuna-on-one-host"></a>

### Sibuna en un solo host

Estas ejecuciones usaron un AMD Ryzen 9 5950X. El daemon tenía cuatro CPU y funcionaba en
memoria; el generador de carga y un origen simulado se ejecutaban en otras ocho CPU. `wrk` usó
64 conexiones por loopback.
Las cifras son medianas de tres ejecuciones.

- En modo forward-auth, todas las cargas alcanzaron de 197.532 a 211.636 peticiones por
  segundo, con un p99 de 305 a 327 us y de 11,7 a 13,8 us de CPU por petición. El límite fue el
  generador de carga.
- Las peticiones a través del proxy alcanzaron de 138.965 a 147.303 por segundo. La memoria
  máxima fue de unos 16 MiB.
- Con una misma carga ofrecida de 100.000 peticiones admitidas por segundo, la latencia p99.9
  fue de 62 us en modo forward-auth y de 150 us en modo proxy inverso.

<a id="beside-anubis"></a>

### Junto a Anubis

Medimos el binario oficial de la versión 1.27.0 de Anubis con las mismas cargas, CPU y
generador de carga. Se igualó el trabajo de Hashcash: 8 bits a cero para Sibuna, 2 dígitos
hexadecimales a cero para Anubis. El origen fue `caddy respond`. La tabla muestra peticiones
admitidas con una sesión.

| Peticiones admitidas | Sibuna Gate | Sibuna Shield | Anubis 1.27.0 |
| --- | ---: | ---: | ---: |
| Forward auth, req/s | 210.682 | 208.635 | 36.509 |
| Forward auth, p99 | 305 us | 308 us | 7.477 us |
| Forward auth, CPU por petición | 12,1 us | 13,2 us | 106,3 us |
| Proxy inverso, req/s | 106.376 | 103.298 | 19.398 |
| Proxy inverso, p99 | 3.331 us | 3.321 us | 11.062 us |

La segunda ejecución midió el tiempo de las operaciones de admisión, cada producto en dos CPU.
Anubis se ejecutó una vez con sus tokens Ed25519 por defecto y otra con tokens HS512.

| Operaciones por segundo | Sibuna (BLAKE3 con clave) | Anubis (Ed25519) | Anubis (HS512) |
| --- | ---: | ---: | ---: |
| Comprobación de sesión válida | 88.104 | 10.951 | 16.976 |
| Comprobación sin autenticar | 78.997 | 28.619 | 27.785 |
| Arranque del desafío | 42.664 | 7.893 | 7.952 |
| Verificación de la prueba | 57.924 | 12.668 | 19.261 |

La memoria máxima de Sibuna se mantuvo cerca de 16 MiB. Anubis usó unos 33 MiB en modo
forward-auth y hasta unos 600 MiB en modo proxy inverso. Anubis es una herramienta capaz y muy
utilizada, y estas filas no son una clasificación. Varias no son comparables de forma directa:
en modo forward-auth Anubis responde algunas rutas por sí mismo, no inspecciona el contenido y
las páginas de desafío son distintas. Las ejecuciones usaron loopback sin TLS, sin navegadores
reales y sin almacenamiento.

Consulta los [registros de rendimiento](benchmarks/results/README.md) para el método, los
rangos y los comandos de reproducción: [product-latest.md](benchmarks/results/product-latest.md),
[latency-latest.md](benchmarks/results/latency-latest.md),
[comparison-latest.md](benchmarks/results/comparison-latest.md) y
[admission-latest.md](benchmarks/results/admission-latest.md).
La parte VIII del libro analiza cada diferencia.

<a id="documentation"></a>

## Documentación

- [Libro](https://insanai.github.io/sibuna/book/): conceptos, algoritmos, ejemplos y mediciones.
- [Whitepaper](https://insanai.github.io/sibuna/whitepaper/): arquitectura, pruebas y detalles de diseño.
- [Guía de operaciones](https://insanai.github.io/sibuna/book/operations.html): instalación y despliegue.
- [Referencia](https://insanai.github.io/sibuna/book/reference.html): detalles de la CLI y del protocolo.
- [Debates de diseño](https://insanai.github.io/sibuna/sid/): decisiones y contratos de ingeniería.
- [Contribuir](CONTRIBUTING.md): compilación desde las fuentes y comprobaciones.

<a id="other-software-to-consider"></a>

## Otras herramientas que considerar

- [Anubis](https://github.com/TecharoHQ/anubis): desafíos de navegador para reducir el tráfico de rastreadores.
- [BunkerWeb](https://github.com/bunkerity/bunkerweb): nginx, ModSecurity, CRS y desafíos de bots.
- [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity): un motor WAF que se usa mediante conectores.
- [Coraza](https://github.com/corazawaf/coraza): una biblioteca WAF en Go compatible con reglas ModSecurity y CRS.
- [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset): reglas de detección de ataques para motores WAF.

Estos proyectos cubren partes distintas de la protección web. El inspector de Sibuna es
integrado; no ejecuta CRS ni otros conjuntos de reglas ModSecurity. Combina Sibuna con un WAF
completo cuando tu aplicación necesite una cobertura de reglas más amplia.

<a id="license"></a>

## Licencia

Sibuna es **LGPL 3.0 o posterior**. La licencia cubre el motor, las bibliotecas, el
solucionador de navegador y la consola, incluida su interfaz WebAssembly.

[LICENSE](LICENSE) describe el alcance. [LICENSES](LICENSES) contiene los términos completos.
[NOTICE](NOTICE) enumera las dependencias. Las fuentes y los scripts de compilación están
disponibles en cada etiqueta de versión.

Sibuna está escrito por Vikrant Rathore con la ayuda de Ronak Rathore y Kanak Rathore.
Las empresas que busquen otros términos de licencia pueden contactar con Vikrant Rathore.
Las bibliotecas y materiales de terceros conservan sus respectivas licencias.
