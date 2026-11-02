( function () {
	'use strict';

	var button = document.getElementById( 'isipsafe-test-connection' );
	var output = document.getElementById( 'isipsafe-test-result' );
	var config = window.isipsafeAdmin;

	if ( ! button || ! output || ! config ) {
		return;
	}

	function show( text, ok ) {
		output.textContent = text;
		output.style.color = ok ? '#008a20' : '#d63638';
	}

	button.addEventListener( 'click', function () {
		var body = new FormData();
		body.append( 'action', config.action );
		body.append( 'nonce', config.nonce );

		button.disabled = true;
		output.style.color = '';
		output.textContent = config.testing;

		fetch( config.ajaxUrl, { method: 'POST', credentials: 'same-origin', body: body } )
			.then( function ( response ) {
				return response.json();
			} )
			.then( function ( json ) {
				var message = json && json.data && json.data.message ? json.data.message : config.failed;
				show( message, !! ( json && json.success ) );
			} )
			.catch( function () {
				show( config.failed, false );
			} )
			.then( function () {
				button.disabled = false;
			} );
	} );
} )();
