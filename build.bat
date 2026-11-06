@echo off
rem CACyber-Agent : compilation de lexecutable Windows unique et statique (Go, sans CGO).
rem Prerequis : Go 1.27+ (variable GO, sinon C:\dev\tools\go1.27.3\go\bin\go.exe, sinon go dans le PATH).
rem Sortie    : bin\CACCyber-Agent.exe
setlocal
cd /d "%~dp0"
if "%VERSION%"=="" set "VERSION=1.0.0"
if "%GO%"=="" if exist "C:\dev\tools\go1.27.3\go\bin\go.exe" set "GO=C:\dev\tools\go1.27.3\go\bin\go.exe"
if "%GO%"=="" set "GO=go"
set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64
set GOTOOLCHAIN=local
echo [1/3] Tests...
"%GO%" test ./...
if errorlevel 1 goto erreur
echo [2/3] Ressources Windows (icone CACyber, version, manifeste) puis compilation (version %VERSION%)...
"%GO%" run github.com/tc-hib/go-winres@v0.3.3 simply --arch amd64 --icon internal\ui\icone-app.png --manifest gui --product-name "CACyber Agent" --product-version %VERSION% --file-version %VERSION% --file-description "CACyber - Agent de scan en lecture seule" --copyright "CACyber" --original-filename CACCyber-Agent.exe --out rsrc
if errorlevel 1 goto erreur
if not exist bin mkdir bin
rem -H windowsgui : logiciel fenetre, aucune console noire au double-clic ; --cli se rattache au terminal.
"%GO%" build -trimpath -ldflags "-s -w -H windowsgui -X main.version=%VERSION%" -o bin\CACCyber-Agent.exe .
if errorlevel 1 goto erreur
echo [3/3] Signature de code : voir README (signtool + certificat EV), etape a realiser sur le poste de signature.
echo.
echo   Executable produit : %~dp0bin\CACCyber-Agent.exe
exit /b 0
:erreur
echo La compilation a echoue.
exit /b 1
