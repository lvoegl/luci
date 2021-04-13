'use strict';
'require view';
'require uci';
'require rpc';


var callGetWgInstances = rpc.declare({
	object: 'status.wireguard',
	method: 'get_wg_instances'
});


function parseIfaces(networkSections, instances) {
	var ifaces = {};

	instances.split('\n').slice(0, -1).forEach(function (instance) {
		var props = instance.split('\t');

		if (ifaces[props[0]]) {
			var peerSection = findPeerSection(
				networkSections, props[0], props[1]
			);
			ifaces[props[0]].peers.push({
				name: peerSection.description,
				public_key: props[1],
				endpoint: props[3] != '(none)' ? props[3] : undefined,
				allowed_ips: peerSection.allowed_ips,
				latest_handshake: props[5],
				transfer_rx: props[6],
				transfer_tx: props[7],
				persistent_keepalive: props[8] != 'off' ?
					props[8] + 's' : undefined,
			});
		} else {
			var serverSection = getNetworkSection(networkSections, props[0]);
			ifaces[props[0]] = {
				public_key: props[2],
				listen_port: props[3],
				addresses: serverSection.addresses,
				allowed_zones: serverSection.allowed_zones,
				fwmark: props[4] != 'off' ? props[4] : undefined,
				peers: []
			};
		}
	});

	return ifaces;
}

function getNetworkSection(networkSections, name) {
	for (var i = 0; i < networkSections.length; i++) {
		if (networkSections[i]['.name'] == name) return networkSections[i];
	}
}

function findPeerSection(networkSections, ifaceName, public_key) {
	for (var i = 0; i < networkSections.length; i++) {
		if (networkSections[i]['.type'] == 'wireguard_' + ifaceName &&
			networkSections[i].public_key == public_key) {
			return networkSections[i];
		}
	}
}

function bytesToStr(bytes) {
	bytes = parseFloat(bytes);
	if (bytes < 1) { return '0 B'; }
	var sizes = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
	var i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
	return Math.round(bytes / Math.pow(1024, i), 2) + ' ' + sizes[i];
}

function timestampToStr(timestamp) {
	if (timestamp < 1) {
		return _('Never');
	}
	var now = new Date();
	var seconds = (now.getTime() / 1000) - timestamp;
	var ago = '';
	if (seconds < 60) {
		ago = parseInt(seconds) + _('s ago');
	} else if (seconds < 3600) {
		ago = parseInt(seconds / 60) + _('m ago');
	} else if (seconds < 86401) {
		ago = parseInt(seconds / 3600) + _('h ago');
	} else {
		ago = _('over a day ago');
	}
	var t = new Date(timestamp * 1000);
	return t.toUTCString() + ' (' + ago + ')';
}

function generateCell(data, isTitle = false) {
	return data.map(function (key) {
		var style = 'width: ' + 100 / data.length + '%; border-top: 0px;';

		if (isTitle) {
			key = E('strong', {}, key);
		} else {
			style += ' white-space: break-spaces;';
		}

		return E('div',
			{ 'class': 'td', 'style': style },
			key
		);
	})
}

function generatePeerRow(name, columns, isTitle = false) {
	var sectionStyle = 'text-align: left; border-top: 0px;';
	if (isTitle) sectionStyle += ' background: rgba(0, 0, 0, 0.07);';

	return E('div', {
		'class': 'tr peer cbi-section-table-row',
		'style': 'text-align: left; display: none;'
	}, [
		E('div', {
			'class': 'td',
			'style': 'padding-left: 14%; font-size: 1.2em;'
		}, name),
		E('div', {
			'class': 'td',
			'style': 'display: flex; justify-content: end;'
		},
			E('div', { 'style': 'width: 87%;' },
				E('div', {
					'class': 'table cbi-section-table',
					'style': 'border: 0px;'
				},
					E('div', {
						'class': 'tr cbi-section-table-row',
						'style': sectionStyle
					},
						generateCell(columns, isTitle)
					)
				)
			)
		)
	]);
}

function generateServerRow(columns, isTitle = false) {
	var tdStyle = 'padding-left: 8px; padding-right: 8px;';
	var trStyle = 'border-top: 0px;';

	if (isTitle) {
		trStyle += ' background: rgba(0, 0, 0, 0.08);'
	} else {
		tdStyle += ' width: 75%;';
	}

	return E('div', { 'class': 'td', 'style': tdStyle },
		E('div', {
			'class': 'table cbi-section-table',
			'style': 'border: 0px;'
		},
			E('div', { 'class': 'tr cbi-section-table-row', 'style': trStyle },
				generateCell(columns, isTitle)
			)
		)
	)
}

return view.extend({
	load: function () {
		return Promise.all([callGetWgInstances(), uci.load('network')]);
	},
	render: function (rpcReplies) {
		var instances = rpcReplies[0].result;
		var networkSections = uci.sections('network');

		var ifaces = Object.entries(parseIfaces(networkSections, instances));
		var ifaceKeys = [
			_('IP Addresses'),
			_('Listen Port'),
			_('Firewall Mark'),
			_('Peers')
		];

		var status = [
			E('div', {
				'class': 'table cbi-section-table',
				'style': 'border: 2px solid #aaa;'
			}, [
				E('div', {
					'class': 'tr server cbi-section-table-row',
					'style': 'font-size: 1.5em;'
				}, [
					E('div', { 'class': 'td', 'style': 'width: 25%;' },
						E('strong', {}, _('Interface'))
					),
					generateServerRow(ifaceKeys, true)
				])
			])
		];

		ifaces.forEach(function (iface) {
			var name = iface[0];
			var config = iface[1];

			var ifaceData = [
				config.addresses.join('\n'),
				config.listen_port,
				config.fwmark,
				config.peers.length
			];

			var rows = [
				E('div',
					{
						'class': 'tr server cbi-section-table-row',
						'data-tooltip': config.peers.length ?
							_('Click to expand/hide Peers') : undefined
					}, [
					E('div',
						{ 'class': 'td', 'style': 'font-size: 1.3em;' },
						name
					),
					generateServerRow(ifaceData)
				])
			];


			if (config.peers.length) {
				var peerKeys = [
					_('Endpoint'),
					_('Allowed IPs'),
					_('Persistent Keepalive'),
					_('Latest Handshake'),
					_('Data Received'),
					_('Data Transmitted')
				];
				rows.push(generatePeerRow(_('Peers'), peerKeys, true));

				config.peers.forEach(function (peer) {
					var peerData = [
						peer.endpoint,
						peer.allowed_ips.join('\n'),
						peer.persistent_keepalive,
						timestampToStr(peer.latest_handshake),
						bytesToStr(peer.transfer_rx),
						bytesToStr(peer.transfer_tx)
					];

					rows.push(generatePeerRow(peer.name, peerData));
				});
			}

			status.push(
				E('div', {
					'class': 'table cbi-section-table',
					'style': 'border: 1px solid #aaa;'
				}, rows)
			);
		});

		var site = E('div', { 'class': 'cbi-section' }, [
			E('h2', {}, _('WireGuard Status')),
			E('div', {}, status),
			E('script', {
				'src': L.resource('view/wireguard/include/toggle.js')
			})
		]);

		return site;
	},
	handleReset: null,
	handleSaveApply: null,
	handleSave: null
});
