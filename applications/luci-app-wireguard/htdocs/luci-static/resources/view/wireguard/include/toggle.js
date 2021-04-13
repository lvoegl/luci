document.querySelectorAll('.tr.server').forEach(function (serverEl) {
	serverEl.addEventListener('click', function (ev) {
		ev.currentTarget.parentElement.querySelectorAll('.tr.peer')
			.forEach(function (peerEl) {
				if (peerEl.style.display == 'none') {
					peerEl.style.removeProperty('display');
				} else {
					peerEl.style.display = 'none';
				}
			});
	});
});
