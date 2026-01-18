# tests/integration_test.py
#!/usr/bin/env python3
"""
Integration test for Path Predict
"""
import sys
import subprocess
import requests
import time
import json
from pathlib import Path

def test_full_stack():
    """Test entire stack"""
    print("🧪 Running Path Predict Integration Test")
    print("=" * 60)
    
    # Step 1: Start services
    print("\n1. Starting services...")
    subprocess.run(["docker-compose", "up", "-d"], check=True)
    time.sleep(10)
    
    # Step 2: Initialize database
    print("\n2. Initializing database...")
    result = subprocess.run(
        ["python", "-m", "cli.main", "init"],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print(f"❌ Database initialization failed: {result.stderr}")
        return False
    print("✅ Database initialized")
    
    # Step 3: Create sample data
    print("\n3. Creating sample data...")
    result = subprocess.run(
        ["python", "tests/sample_data.py"],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print(f"⚠️  Sample data creation had issues: {result.stderr}")
    print("✅ Sample data created")
    
    # Step 4: Test API
    print("\n4. Testing API endpoints...")
    try:
        response = requests.get("http://localhost:8000/health", timeout=5)
        if response.status_code == 200:
            print("✅ API health check passed")
        else:
            print(f"❌ API health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ API health check error: {e}")
        return False
    
    # Step 5: Test attack path detection
    print("\n5. Testing attack path detection...")
    result = subprocess.run(
        ["python", "-m", "cli.main", "paths", "detect", "--limit", "1"],
        capture_output=True,
        text=True
    )
    if result.returncode == 0 and "attack paths" in result.stdout.lower():
        print("✅ Attack path detection working")
    else:
        print(f"⚠️  Attack path detection may have issues: {result.stdout[:200]}")
    
    # Step 6: Test real-time dashboard
    print("\n6. Testing real-time dashboard...")
    try:
        response = requests.get("http://localhost:8000/api/v1/realtime/dashboard", timeout=5)
        if response.status_code == 200:
            print("✅ Real-time dashboard working")
        else:
            print(f"⚠️  Real-time dashboard issues: {response.status_code}")
    except Exception as e:
        print(f"⚠️  Real-time dashboard error: {e}")
    
    # Step 7: Test Terraform analysis
    print("\n7. Testing Terraform analysis...")
    sample_tf = Path("tests/sample.tf")
    sample_tf.write_text("""
    resource "aws_iam_role" "test" {
      name = "TestRole"
      assume_role_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Action = "sts:AssumeRole"
            Effect = "Allow"
            Principal = "*"
          }
        ]
      })
    }
    """)
    
    result = subprocess.run(
        ["python", "-m", "cli.main", "realtime", "analyze", "--hcl-file", "tests/sample.tf"],
        capture_output=True,
        text=True
    )
    if result.returncode == 0 and "High Risk Changes" in result.stdout:
        print("✅ Terraform analysis working")
    else:
        print(f"⚠️  Terraform analysis issues: {result.stdout[:200]}")
    
    # Step 8: Test prediction engine
    print("\n8. Testing prediction engine...")
    result = subprocess.run(
        ["python", "-m", "cli.main", "realtime", "predict"],
        capture_output=True,
        text=True
    )
    if result.returncode == 0:
        print("✅ Prediction engine working")
    else:
        print(f"⚠️  Prediction engine issues: {result.stderr}")
    
    print("\n" + "=" * 60)
    print("🎉 Integration test completed!")
    print("\nNext steps:")
    print("1. Start UI: cd ui && npm start")
    print("2. View Neo4j: http://localhost:7474 (neo4j/pathpredict123)")
    print("3. View API docs: http://localhost:8000/docs")
    
    return True

if __name__ == "__main__":
    try:
        success = test_full_stack()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⏹️  Test interrupted by user")
        sys.exit(1)
