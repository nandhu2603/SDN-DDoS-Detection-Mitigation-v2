# ==============================================================================
# Windows PowerShell Startup Script: SDN DDoS Detection & Mitigation Lab
# ==============================================================================

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   SDN DDoS Detection & Mitigation System - Windows Launcher" -ForegroundColor Cyan
Write-Host "   Tech: Ryu Controller Simulation + ML Classifier + Live Dashboard" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# 1. Check Python
$pythonBin = ".\venv\Scripts\python.exe"
if (-not (Test-Path $pythonBin)) {
    $pythonBin = "python"
}

# 2. Check models
if (-not (Test-Path "ml\models\model.pkl")) {
    Write-Host "[STEP 1/3] Generating dataset and training ML models..." -ForegroundColor Yellow
    & $pythonBin ml\train_model.py
    & $pythonBin ml\evaluate.py
} else {
    Write-Host "[STEP 1/3] ML models verified." -ForegroundColor Green
}

# 3. Create logs dir
if (-not (Test-Path "logs")) { New-Item -ItemType Directory -Path "logs" | Out-Null }

# 4. Start Dashboard
Write-Host "[STEP 2/3] Starting Flask Web Dashboard on http://127.0.0.1:5000 ..." -ForegroundColor Green
$dashProc = Start-Process -FilePath $pythonBin -ArgumentList "dashboard\app.py" -PassThru -NoNewWindow

# 5. Start Controller Simulation
Write-Host "[STEP 3/3] Starting Controller Simulation loop..." -ForegroundColor Green
$ctrlProc = Start-Process -FilePath $pythonBin -ArgumentList "controller\ddos_controller.py --simulate" -PassThru -NoNewWindow

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " [DEMO READY] Lab is running!" -ForegroundColor Green
Write-Host "   - Web Dashboard: http://127.0.0.1:5000" -ForegroundColor White
Write-Host "   - Open your browser to test live detection and mitigation!" -ForegroundColor White
Write-Host "   - Press Enter to stop background processes..." -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Cyan

Read-Host
Stop-Process -Id $dashProc.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $ctrlProc.Id -Force -ErrorAction SilentlyContinue
Write-Host "[INFO] All services stopped." -ForegroundColor Green
