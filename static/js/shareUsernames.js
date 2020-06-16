function showUsernames(element, usernames) {
    element.innerHTML += `: ${usernames}`;
}

function hideUsernames(element, sharecount) {
    element.innerHTML = `Shared with ${sharecount} other profile(s)`
}