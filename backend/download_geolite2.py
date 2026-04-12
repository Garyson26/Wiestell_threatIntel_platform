#!/usr/bin/env python3
"""Download MaxMind GeoLite2 database using license key."""

import os
import tarfile
import shutil
from pathlib import Path
import requests
from dotenv import load_dotenv

load_dotenv()

# MaxMind configuration
ACCOUNT_ID = os.getenv("MAXMIND_ACCOUNT_ID")
LICENSE_KEY = os.getenv("MAXMIND_LICENSE_KEY")
DB_PATH = os.getenv("GEOIP_DB_PATH", "./data/GeoLite2-City.mmdb")

# MaxMind download URL format
DOWNLOAD_URL = (
    f"https://download.maxmind.com/app/geoip_download"
    f"?edition_id=GeoLite2-City"
    f"&license_key={LICENSE_KEY}"
    f"&suffix=tar.gz"
)

def download_geolite2():
    """Download and extract GeoLite2-City database."""
    
    if not ACCOUNT_ID or not LICENSE_KEY:
        print("❌ MaxMind credentials not found in .env file")
        print("   Please set MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY")
        return False
    
    print(f"✓ MaxMind Account ID: {ACCOUNT_ID}")
    print(f"✓ License Key: {LICENSE_KEY[:8]}****")
    print(f"✓ Target DB path: {DB_PATH}")
    
    # Create data directory if it doesn't exist
    data_dir = Path(DB_PATH).parent
    data_dir.mkdir(exist_ok=True, parents=True)
    print(f"✓ Data directory: {data_dir}")
    
    # Download the database
    print(f"\n📡 Downloading GeoLite2-City database...")
    try:
        response = requests.get(DOWNLOAD_URL, stream=True)
        response.raise_for_status()
        
        # Save to temporary file
        temp_tar = data_dir / "GeoLite2-City.tar.gz"
        with open(temp_tar, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        print(f"✓ Downloaded to: {temp_tar}")
        print(f"✓ File size: {temp_tar.stat().st_size / 1024 / 1024:.2f} MB")
        
    except requests.exceptions.HTTPError as e:
        print(f"❌ HTTP Error: {e}")
        if e.response.status_code == 401:
            print("   Invalid license key or account ID")
        elif e.response.status_code == 403:
            print("   Access forbidden - check your MaxMind account status")
        return False
    except Exception as e:
        print(f"❌ Download failed: {e}")
        return False
    
    # Extract the database
    print(f"\n📦 Extracting database...")
    try:
        with tarfile.open(temp_tar, 'r:gz') as tar:
            # Find the .mmdb file in the archive
            mmdb_file = None
            for member in tar.getmembers():
                if member.name.endswith('.mmdb'):
                    mmdb_file = member
                    break
            
            if not mmdb_file:
                print("❌ No .mmdb file found in archive")
                return False
            
            # Extract to temporary location
            tar.extract(mmdb_file, data_dir)
            extracted_path = data_dir / mmdb_file.name
            
            # Move to final location
            target_path = Path(DB_PATH)
            shutil.move(str(extracted_path), str(target_path))
            
            print(f"✓ Extracted to: {target_path}")
            print(f"✓ Database size: {target_path.stat().st_size / 1024 / 1024:.2f} MB")
        
        # Clean up
        temp_tar.unlink()
        
        # Remove extracted directory
        for item in data_dir.iterdir():
            if item.is_dir() and 'GeoLite2' in item.name:
                shutil.rmtree(item)
        
        print(f"\n✅ GeoLite2 database installed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Extraction failed: {e}")
        return False

def test_database():
    """Test the GeoLite2 database."""
    print(f"\n🧪 Testing GeoLite2 database...")
    
    try:
        import geoip2.database
        
        db_path = Path(DB_PATH)
        if not db_path.exists():
            print(f"❌ Database file not found: {db_path}")
            return False
        
        reader = geoip2.database.Reader(str(db_path))
        
        # Test with a known IP (Google DNS)
        test_ip = "8.8.8.8"
        response = reader.city(test_ip)
        
        print(f"✓ Database loaded successfully")
        print(f"\n   Test IP: {test_ip}")
        print(f"   Country: {response.country.name} ({response.country.iso_code})")
        print(f"   City: {response.city.name or 'N/A'}")
        print(f"   Location: {response.location.latitude}, {response.location.longitude}")
        
        reader.close()
        print(f"\n✅ GeoIP enrichment is ready!")
        return True
        
    except ImportError:
        print(f"❌ geoip2 library not installed")
        print(f"   Install with: pip install geoip2")
        return False
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("MaxMind GeoLite2 Database Installer")
    print("=" * 60)
    
    if download_geolite2():
        test_database()
    else:
        print(f"\n❌ Installation failed")
        exit(1)
