var fs = require('fs');
var assert = require("assert");
var async = require('async');

var Class = require("pixl-class");
var Tools = require("pixl-tools");
var PixlRequest = require("pixl-request");

module.exports = Class.create({
	
	__mixins: [
		require('./api/config.js'),
		require('./api/admin.js'),
		require('./api/apikey.js'),
		require('./api/alerts.js'),
		require('./api/commands.js'),
		require('./api/groups.js'),
		require('./api/monitors.js'),
		require('./api/submit.js'),
		require('./api/view.js'),
		require('./api/file.js')
	],
	
	api_ping: function(args, callback) {
		// hello
		callback({ code: 0 });
	},
	
	api_echo: function(args, callback) {
		setTimeout( function() {
			callback({
				code: 0,
				query: args.query || {},
				params: args.params || {},
				files: args.files || {}
			});
		}, 1000 );
	},
	
	api_stats: function(args, callback) {
		// web server stats
		callback({ code: 0, stats: this.web.getStats() });
	},
	
	api_check_user_exists: function(args, callback) {
		var query = args.query;
		var path = 'users/' + this.usermgr.normalizeUsername(query.username);
		
		if (!this.requireParams(query, {
			username: this.usermgr.usernameMatch
		}, callback)) return;
		
		this.forceNoCacheResponse(args);
		
		this.storage.get(path, function(err, user) {
			callback({ code: 0, user_exists: !!user });
		} );
	},
	
	
	getServerBaseAPIURL: function(hostname) {
		var api_url = '';
		
		if (this.web.config.get('https') && this.web.config.get('https_force')) {
			api_url = 'https://' + hostname;
			if (this.web.config.get('https_port') != 443) api_url += ':' + this.web.config.get('https_port');
		}
		else {
			api_url = 'http://' + hostname;
			if (this.web.config.get('http_port') != 80) api_url += ':' + this.web.config.get('http_port');
		}
		api_url += this.api.config.get('base_uri');
		
		return api_url;
	},
	
	requireValidUser: function(session, user, callback) {
		
		if (session && (session.type == 'api')) {
			if (!user) {
				return this.doError('api', "Invalid API Key: " + session.api_key, callback);
			}
			if (!user.active) {
				return this.doError('api', "API Key is disabled: " + session.api_key, callback);
			}
			return true;
		} // api key
		
		if (!session) {
			return this.doError('session', "Session has expired or is invalid.", callback);
		}
		if (!user) {
			return this.doError('user', "User not found: " + session.username, callback);
		}
		if (!user.active) {
			return this.doError('user', "User account is disabled: " + session.username, callback);
		}
		return true;
	},
	
	requireAdmin: function(session, user, callback) {

		if (!this.requireValidUser(session, user, callback)) return false;
		
		if (session.type == 'api') {
			// API Keys cannot be admins
			return this.doError('api', "API Key cannot use administrator features", callback);
		}
		
		if (!user.privileges.admin) {
			return this.doError('user', "User is not an administrator: " + session.username, callback);
		}
		
		return true;
	},
	
	loadSession: function(args, callback) {
		var self = this;
		var session_id = args.cookies['session_id'] || args.request.headers['x-session-id'] || args.params.session_id || args.query.session_id;
		
		if (session_id) {
			this.logDebug(9, "Found Session ID: " + session_id);
			
			this.storage.get('sessions/' + session_id, function(err, session) {
				if (err) return callback(err, null, null);
				

				self.storage.get('users/' + self.usermgr.normalizeUsername(session.username), function(err, user) {
					if (err) return callback(err, null, null);
					
					// set type to discern this from API Key sessions
					session.type = 'user';
					
					// get session_id out of args.params, so it doesn't interfere with API calls
					delete args.params.session_id;
		
					callback(null, session, user);
				} );
			} );
			return;
		}
		
		var api_key = args.request.headers['x-api-key'] || args.params.api_key || args.query.api_key;
		if (!api_key) return callback( new Error("No Session ID or API Key could be found"), null, null );
		
		this.logDebug(9, "Found API Key: " + api_key);
		
		this.storage.listFind( 'global/api_keys', { key: api_key }, function(err, item) {
			if (err) return callback(new Error("API Key is invalid: " + api_key), null, null);
			
			var session = {
				type: 'api',
				api_key: api_key
			};
			var user = item;
		return;
	},
	
	requireParams: function(params, rules, callback) {
		// proxy over to user module
		assert( arguments.length == 3, "Wrong number of arguments to requireParams" );
		return this.usermgr.requireParams(params, rules, callback);
	},
	
	doError: function(code, msg, callback) {
		// proxy over to user module
		assert( arguments.length == 3, "Wrong number of arguments to doError" );
		return this.usermgr.doError( code, msg, callback );
	}
	
});
