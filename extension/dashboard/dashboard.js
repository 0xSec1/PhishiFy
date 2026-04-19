let isSignUp = false;

const authView = document.getElementById('auth-view');
const dashboardView = document.getElementById('dashboard-view');
const authTitle = document.getElementById('auth-title');
const authBtn = document.getElementById('auth-btn');
const togglePrompt = document.getElementById('toggle-prompt');
const toggleLink = document.getElementById('toggle-link');
const userEmailSpan = document.getElementById('user-email');

function toggleAuth() {
    isSignUp = !isSignUp;
    if (isSignUp) {
        authTitle.innerText = "Create Account";
        authBtn.innerText = "Sign Up";
        togglePrompt.innerText = "Already have an account?";
        toggleLink.innerText = "Sign In";
    } else {
        authTitle.innerText = "Sign In to PhishiFy";
        authBtn.innerText = "Sign In";
        togglePrompt.innerText = "Don't have an account?";
        toggleLink.innerText = "Sign Up";
    }
}

toggleLink.addEventListener('click', toggleAuth);

authBtn.addEventListener('click', () => {
    const email = document.getElementById('email').value;
    const pwd = document.getElementById('password').value;
    if (!email || !pwd) {
        alert("Please enter both email and password.");
        return;
    }

    // Better Auth mockup utilizing chrome.storage rather than accessible localstorage
    // Ideal production flow hits backend API and retrieves jwt/cookie instead 
    chrome.storage.local.set({ phishify_user: email }, () => {
        showDashboard(email);
    });
});

document.getElementById('logout-btn').addEventListener('click', () => {
    chrome.storage.local.remove('phishify_user', () => {
        checkAuth();
    });
});

function showDashboard(email) {
    authView.style.display = 'none';
    dashboardView.style.display = 'block';
    userEmailSpan.innerText = email || "User";
    
    // Fetch stats from background process cleanly
    if (chrome && chrome.runtime && chrome.runtime.sendMessage) {
        try {
            chrome.runtime.sendMessage({ action: "get_stats" }, response => {
                if (chrome.runtime.lastError) {
                    console.warn("Background not ready:", chrome.runtime.lastError.message);
                    return;
                }
                if (response) {
                    document.getElementById('stat-scanned').innerText = response.checked || 0;
                    document.getElementById('stat-clean').innerText = response.clean || 0;
                    document.getElementById('stat-phish').innerText = response.suspicious || 0;
                }
            });
        } catch(e) {}
    }
}

function checkAuth() {
    if (chrome && chrome.storage) {
        chrome.storage.local.get(['phishify_user'], function(result) {
            if (result.phishify_user) {
                showDashboard(result.phishify_user);
            } else {
                dashboardView.style.display = 'none';
                authView.style.display = 'block';
            }
        });
    } else {
        // Fallback if opened purely local
        dashboardView.style.display = 'none';
        authView.style.display = 'block';
    }
}

// Initial Check
checkAuth();
