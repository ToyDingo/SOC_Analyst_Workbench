Project Title
SOC_Analyst_Workbench
A lightweight SOC investigation platform for log ingestion, detection, and AI-assisted incident reporting.

Description
SOC_Analyst_Workbench is a full-stack Security Operations Center (SOC) investigation application designed to simulate and streamline the log analysis workflow used by security analysts. The platform allows users to upload structured security logs (e.g., web proxy or Zscaler-style logs), ingest them into a PostgreSQL-backed event store, run detection logic to identify suspicious patterns, and generate AI-assisted SOC reports that summarize incidents, timelines, indicators of compromise (IOCs), and recommended response actions.

The application is composed of a FastAPI backend API, a Next.js frontend UI, and a PostgreSQL database, all containerized with Docker. It is designed to run locally via Docker Compose and can later be deployed to cloud environments such as Google Cloud Platform.

Repository
The source code can be cloned from:
[https://github.com/ToyDingo/SOC_Analyst_Workbench]

Getting Started

Dependencies
The following software must be installed before running the application locally:

* Windows 10/11, macOS, or modern Linux distribution
* Docker Desktop (latest stable version recommended)
* Git
* At least 4GB RAM available for Docker

Installing

1. Clone the repository

Open a terminal and run:

git clone [https://github.com/ToyDingo/SOC_Analyst_Workbench.git]

2. Navigate into the project directory

cd SOC_Analyst_Workbench

3. Create a .env file in the project root (if not already present)

Example minimal .env configuration:

DATABASE_URL=postgresql://app:app@db:5432/app
JWT_SECRET=supersecretkey
MAX_UPLOAD_BYTES=5000000
NEXT_PUBLIC_API_BASE_URL=[http://localhost:8000]

Adjust values as needed for your environment.

Executing Program

To build and start all services (API, Web UI, and Database), run:

docker compose up --build

This will:

* Build the FastAPI backend container
* Build the Next.js frontend container
* Start a PostgreSQL database container
* Expose:

  * Frontend at [http://localhost:3000]
  * Backend API at [http://localhost:8000]

After containers are running:

1. Open a browser.
2. Navigate to [http://localhost:3000]
3. Register a new user account.
4. Log in.
5. Upload a supported log file.
6. Wait for ingestion to complete.
7. Run detections.
8. Generate a SOC report.

To stop the application:

docker compose down

To remove volumes (reset database state):

docker compose down -v

Help

If you encounter issues:

1. Verify Docker is running.
2. Confirm ports 3000 and 8000 are not already in use.
3. Check container logs:

docker compose logs

To view logs for a specific service:

docker compose logs api
docker compose logs web
docker compose logs db

If database schema issues occur, you may need to:

docker compose down -v
docker compose up --build

Authors

Kevin Ford
GitHub: [https://github.com/ToyDingo]
