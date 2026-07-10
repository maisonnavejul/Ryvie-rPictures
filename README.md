<p align="center"> 
  <br/>
  <a href="https://opensource.org/license/agpl-v3"><img src="https://img.shields.io/badge/License-AGPL_v3-blue.svg?color=3F51B5&style=for-the-badge&label=License&logoColor=000000&labelColor=ececec" alt="License: AGPLv3"></a>
  <br/>
  <br/>
</p>

<p align="center">
  <img src="./web/static/rpictures-logo.png" width="300" alt="rPictures logo">
</p>

<h1 align="center">rPictures</h1>

<p align="center"><strong>English</strong> · <a href="README.fr.md">Français</a></p>

> Part of the [Ryvie](https://github.com/ryvieos/Ryvie) ecosystem, the self-hosted personal cloud OS. Learn more at [ryvie.fr](https://ryvie.fr).

<h3 align="center">Self‑hosted photo and video gallery for your personal cloud</h3>

<br/>

---

## Overview

**rPictures** is a self‑hosted photo and video gallery for your personal cloud, a Google Photos alternative that runs on your own server (at home or on a VPS) while keeping **full control of your data**. It lets you back up, organize and browse your photos and videos with a modern experience.

rPictures is built specifically for **RyvieOS**, the personal cloud operating system for the home. It integrates natively into that ecosystem to provide a consistent "Photos/Videos" building block alongside the other services (files, notes, etc.).

rPictures is a **fork** of the open source project [Immich](https://github.com/immich-app/immich). It builds on its technical and functional foundations, while being adapted and optimized for the RyvieOS environment.

---

## Why rPictures?

- **Self‑hosted at home**  
  Deploy rPictures on your own server (NUC, mini‑PC, NAS, VPS…) and keep your memories close to you.

- **Data control and privacy**  
  No opaque SaaS solution: your photos and videos stay under your control, encrypted and stored wherever you decide.

- **Modern experience**  
  Modern interface, advanced search, shared albums, automatic backup from mobile: an experience close to the major platforms, but without the drawbacks.

- **Designed for RyvieOS**  
  Built natively for **RyvieOS**, the personal cloud operating system: integrated LDAP authentication, monitoring, automatic backups and centralized service management.

- **Based on a mature project**  
  Built on a robust technical base from the original Immich project, benefiting from its experience and its community.

---

## Links

- **Source code**: https://github.com/ryvieos/Ryvie-rPictures  
- **RyvieOS website**: https://ryvie.fr  
- **Documentation**: coming soon (refer to the GitHub repository)  
- **Issue tracking / feature requests**: https://github.com/ryvieos/Ryvie-rPictures/issues  
- **Roadmap**: coming soon  
- **Demo**: see the section below

---

## Demo

A public demo will be **available soon**.

In the meantime, you can try rPictures locally or on your own server by following the **Installation** and **Deployment with Docker Compose** section below.

---

## Features

The list below covers the main features available in rPictures, on **mobile** and **web**:

| Feature                                             | Mobile | Web |
| :-------------------------------------------------- | :----: | :--: |
| Upload and view photos and videos                   |  Yes   | Yes |
| Automatic backup on app launch                      |  Yes   | N/A |
| Media duplication prevention                        |  Yes   | Yes |
| Album selection for backup                          |  Yes   | N/A |
| Download to local device                            |  Yes   | Yes |
| Multi‑user support                                  |  Yes   | Yes |
| Albums and shared albums                            |  Yes   | Yes |
| Fast / scrubbable scroll bar                        |  Yes   | Yes |
| RAW format support                                  |  Yes   | Yes |
| Metadata view (EXIF, map, etc.)                     |  Yes   | Yes |
| Search by metadata, objects, faces, CLIP            |  Yes   | Yes |
| Administration functions (account management)       |  No    | Yes |
| Background backup                                   |  Yes   | N/A |
| Virtual scroll (smooth large galleries)             |  Yes   | Yes |
| OAuth support                                       |  Yes   | Yes |
| API keys                                            |  N/A   | Yes |
| LivePhoto / MotionPhoto backup/playback             |  Yes   | Yes |
| 360° image support                                  |  No    | Yes |
| User‑defined storage structure                      |  Yes   | Yes |
| Public sharing                                      |  Yes   | Yes |
| Archive and favorites                               |  Yes   | Yes |
| Global map                                          |  Yes   | Yes |
| Partner sharing                                     |  Yes   | Yes |
| Facial recognition and grouping                     |  Yes   | Yes |
| Memories (x years ago)                              |  Yes   | Yes |
| Offline support                                     |  Yes   | No  |
| Read‑only gallery                                   |  Yes   | Yes |
| Stacked photos                                      |  Yes   | Yes |
| Tags / labels                                       |  No    | Yes |
| Folder view                                         |  Yes   | Yes |

> Note: some features may require additional services (search engine, machine learning service, etc.), usually provided via Docker.

---

## Tech stack (overview)

rPictures is made up of several services, typically deployed via **Docker Compose**:

- **Application services**  
  Backend and web services to manage user accounts, albums, the API, synchronization, etc.

- **Database**  
  Relational database (for example PostgreSQL) for metadata and user management.

- **Cache / message queue**  
  Cache / queue service (for example Redis) for job management, sessions and some asynchronous operations.

- **Search engine & ML**  
  Auxiliary services for text / similarity search, face detection, object detection, etc.

- **Client applications**  
  - rPictures web application  
  - Mobile applications (Android / iOS) based on the client compatible with the rPictures backend

The precise details of the stack and the deployed services are described in the repository's Docker configuration files (`docker/` folder).

---

## Installation

### Requirements

- A Linux server (or local machine) with:
  - Docker and the Docker Compose plugin
  - A stable network connection
  - Enough disk space to store your photos/videos
- A domain name (optional but recommended) if you expose rPictures on the Internet
- **RyvieOS** (recommended) for full integration with LDAP authentication, monitoring and automatic backups

### Get the code

```bash
git clone https://github.com/ryvieos/Ryvie-rPictures.git
cd Ryvie-rPictures
```

### Quick deployment with Docker Compose

A standard example is to use the files provided in the `docker/` folder:

```bash
# From the repository root
docker compose -f docker/docker-compose.yml up -d
```

This command:

- Downloads the required images
- Starts the rPictures services (API, web, technical services…)
- Creates the necessary volumes for data and metadata

> Remember to check and adapt the `docker-compose.yml` file (exposed ports, volume paths, etc.) before a production deployment.

### First login

1. Once the containers are started, open the web interface:  
   `http://your‑server:PORT` (PORT according to your Docker configuration, for example `2283` or another value you set).
2. Create an administrator account if needed (or use the initial user configured by the application).
3. Configure:
   - Your backup folders
   - The interface language
   - The recognition settings (if enabled)

---

## Configuration

rPictures is configured mainly via:

- **Environment variables**  
  For access to the database, the cache, the search services, the storage paths, etc.  
  These variables are usually defined in:
  - The `docker-compose.yml` files
  - An optional `.env` file loaded by Docker

- **Docker volumes**  
  For the storage directories of originals, thumbnails, derived files, etc.

Points to watch:

- **Storage**:  
  - Define a volume for photos/videos, for example mounted to `/photos` in the container.  
  - Make sure this volume is backed up by your backup routines (NAS, external drive, etc.).

- **Backups**:  
  - Follow as much as possible the **3‑2‑1** rule (3 copies, 2 different media, 1 off‑site) for your photos/videos.  
  - rPictures does not replace a complete backup strategy.

- **Security & access**:  
  - Place rPictures behind a reverse proxy (for example Traefik, Caddy, Nginx) to handle TLS/HTTPS.  
  - Restrict administrative access to trusted users.

---

## Contributing

Contributions to rPictures are welcome!

- **Report a bug**: open an issue with:
  - The rPictures version
  - Your configuration (Docker, OS, etc.)
  - The steps to reproduce the problem
- **Propose a new feature**: create a *feature request* issue explaining the need, the context (especially with RyvieOS) and a usage example.
- **Send a Pull Request**:
  - Fork the repository: https://github.com/ryvieos/Ryvie-rPictures
  - Create a dedicated branch
  - Add your changes with tests if possible
  - Open a PR clearly describing your change

Before contributing, check any guidelines in `CONTRIBUTING.md` or the repository documentation if they exist.

---

## Original project

rPictures is based on the open source project **Immich**:

- **Original project**: Immich – Self‑hosted photo and video management solution  
- **Original repository**: https://github.com/immich-app/immich  

Many thanks to the entire Immich team and community for their outstanding work, which serves as a solid foundation for rPictures.

---

## License

rPictures is distributed under the **AGPLv3** license (Affero General Public License version 3), in accordance with the original project.

For more details, see the `LICENSE` file at the root of the repository or the page:  
https://opensource.org/license/agpl-v3

---

## Authors & contributors

<a href="https://github.com/ryvieos/Ryvie-rPictures/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=ryvieos/Ryvie-rPictures" width="100%" alt="rPictures contributors"/>
</a>

Thanks to everyone who helps rPictures evolve and build a privacy‑respecting personal cloud with RyvieOS.
