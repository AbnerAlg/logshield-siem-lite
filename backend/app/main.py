import shutil
from pathlib import Path
from typing import List
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# Import Modules 
from app.parser.log_parser import parse_log_file
from app.rules.detection import analyze_security_threats
from app.rules.models import SecurityAlert

# Initialize the FastAPI application
app = FastAPI(
    title = "LogShield SIEM Lite API",
    description = "REST API to ingest server logs and analyze security threads automatically. ",
    version = "1.0.0"
)

# Eneable CORS (Cross-Origin Resource Sharing) so our future Vue.js fronted can connect
app.add_middleware(
    CORSMiddleware,
    allow_origins = ["*"],
    allow_credentials = True,
    allow_methods = ["*"],
    allow_headers = ["*"],
)

@app.get("/")
def read_root():
    """ Health check endpoint to verify the SIEM API is up and running """
    return {
        "status" : "online",
        "service" : "LogShield SIEM Lite",
        "version" : "1.0.0"
    }

@app.post("/api/v1/logs/upload", response_model=List[SecurityAlert])
async def upload_and_analyze_log(file: UploadFile = File(...)):
    """ Ingest a raw log file (.log or .txt), runs the parsing engine
        evaluates security rules, and returns a list of detected threats. """
    
    # Validate file extension for security and operational consistency
    if not file.filename.endswith(('.log', '.txt')):
        raise HTTPException(
            status_code=400,
            detail="Invalid file format. Only .log and .txt files are accepted. "
        )
    
    # Define a temporary path inside the backend to write the uploaded file safely 
    temp_dir = Path(__file__).resolve().parent.parent / "temp"
    temp_dir.mkdir(exist_ok=True)
    temp_file_path = temp_dir / file.filename

    try:
        # Save the uploaded file stream into the temporary local path 
        with temp_file_path.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

            # Step 1: Run the Parser Engine 
            parsed_events = parse_log_file(temp_file_path)

            if not parsed_events:
                raise HTTPException(
                    status_code=422,
                    detail="The log file could not be parsed. Verify it matches the Standard Common Log Format (CLF)"
                )
            
            # Step 2: Run the Security Rule Engine
        detected_alerts = analyze_security_threats(parsed_events)

        return detected_alerts

    except Exception as error:
        # High-level catch block to prevent app crashing and log internal server errors
        raise HTTPException(status_code=500, detail=f"Internal Server Error during analysis: {str(error)}")
    
    finally:
        # Clean up: Always delete the temporary file after processing to save disk space
        if temp_file_path.exists():
            temp_file_path.unlink()