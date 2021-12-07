
var assert = require("assert");
var fs = require("fs");
var os = require("os");
var Path = require("path");
var cp = require("child_process");
var zlib = require('zlib');
var mkdirp = require('mkdirp');
var async = require('async');
var glob = require('glob');

var Class = require("pixl-class");
var Component = require("pixl-server/component");
var Tools = require("pixl-tools");
var Request = require("pixl-request");

module.exports = Class.create({
	
	__name: 'Server Monitor Portal',
	__parent: Component,
	__mixins: [ 
		require('./api.js')   // API Layer Mixin
	],
	
	systems: [
		{
			id: "hourly",
			date_format: "[yyyy]/[mm]/[dd]/[hh]",
			epoch_div: 60, 
			single_only: true
		},
		{
			id: "daily",
			date_format: "[yyyy]/[mm]/[dd]",
			epoch_div: 120, 
		},
	
	startup: function(callback) {
		// start app service
		var self = this;
		this.logDebug(3, "Starting up", process.argv );
	
		this.storage = this.server.Storage;
		this.web = this.server.WebServer;
		this.api = this.server.API;
		this.usermgr = this.server.User;
	
		this.hostnameCache = {};
		this.groupCache = {};
		this.alertCache = {};
		
		this.api.addNamespace( "app", "api_", this )
		
		// register when users are created / updated / deleted
		this.usermgr.registerHook( 'after_create', this.afterUserChange.bind(this, 'user_create') );
		this.usermgr.registerHook( 'after_update', this.afterUserChange.bind(this, 'user_update') );
		this.usermgr.registerHook( 'after_delete', this.afterUserChange.bind(this, 'user_delete') );
		this.usermgr.registerHook( 'after_login', this.afterUserLogin.bind(this) );
		
		this.usermgr.registerHook( 'before_create', this.beforeUserChange.bind(this) );
		this.usermgr.registerHook( 'before_update', this.beforeUserChange.bind(this) );
		
		this.usermgr.registerHook( 'before_login', this.beforeUserLogin.bind(this) );
		this.usermgr.registerHook( 'before_resume_session', this.beforeUserLogin.bind(this) );
		
		// archive logs daily at midnight
		this.server.on('day', function() {
			self.archiveLogs();
		} );
		
		// enable storage 
		this.server.on(this.server.config.get('maintenance'), function() {
			self.storage.runMaintenance( new Date(), self.runMaintenance.bind(self) );
		});
		
		// update more records on the minute
		this.server.on('minute', function(dargs) {
			self.summarizeMinuteData(dargs);
			self.monitorSelf();
		} );
		
		this.request = new Request( + this.server.__version );
		this.request.setTimeout( 30 * 1000 );
		this.request.setFollow( 5 );
		this.request.setAutoError( true );
		this.request.setKeepAlive( true );
		
		async.series(
			[
				function(callback) {
					self.storage.listGet( 'global/alerts', 0, 0, function(err, items) {
						if (err) return callback(err);
						self.alerts = items;
						callback();
					});
				},
				function(callback) {
					self.storage.listGet( 'global/commands', 0, 0, function(err, items) {
						if (err) return callback(err);
						self.commands = items;
						callback();
					});
				},
				function(callback) {
					self.storage.listGet( 'global/groups', 0, 0, function(err, items) {
						if (err) return callback(err);
						self.groups = items;
						callback();
					});
				},
				function(callback) {
					self.storage.listGet( 'global/monitors', 0, 0, function(err, items) {
						if (err) return callback(err);
						self.monitors = items;
						callback();
					});
				},
				function(callback) {
					self.storage.get( 'global/state', function(err, data) {
						if (err) return callback(err);
						self.state = data;
						callback();
					});
				}
			],
			function(err) {
				if (err) return callback(err);
	},

		async.eachLimit( this.systems, this.storage.concurrency,
			function(sys, callback) {
				self.summarizeMinuteSystem({
					sys: sys,
					epoch: epoch,
					hostnames: hostname_cache[ sys.id ],
				}, callback);
			},
			function(err) {
				if (err) {
					self.logError('summary', "Failed to summarize data: " + (err.message || err));
				}
				
				// finally, write out group data to a list
				self.writeGroupAlertData( epoch, function(err) {
					if (err) {
						self.logError('summary', "Failed to write group data: " + (err.message || err));
					}
					self.logDebug(9, "Minute summary complete");
				});
			}
		);
	
	writeGroupAlertData: function(epoch, callback) {
		// write out group and alert data (totals and count) to list
		var self = this;
		var epoch_div = Math.floor( epoch / 60 );
		var group_data = {
			groups: Tools.copyHash( this.groupCache, true ),
			date: epoch_div * 60, // floored to minute
			epoch_div: epoch_div
		};
		this.groupCache = {};
		this.storage.listPush( 'timeline/overview', group_data, function(err) {
			if (err) return callback(err);
			
			var alert_data = {
				hostnames: Tools.copyHash( self.alertCache, true ),
				date: epoch_div * 60, // floored to minute
			};
			self.alertCache = {};
			
			self.storage.put( 'current/alerts', alert_data, callback );
		} );
	},
	
	summarizeMinuteSystem: function(args, callback) {
		// summarize data for a specific system
		var self = this;
		var sys = args.sys;
		var epoch = args.epoch;
		var epoch_div = Math.floor( epoch / sys.epoch_div );
		var dargs = Tools.getDateArgs( epoch );
		var hostnames = args.hostnames;
		this.logDebug(9, "Summarizing " + sys.id + " system for minute: " + dargs.yyyy_mm_dd + " " + dargs.hh_mi_ss);
		
		if (!hostnames || !Tools.numKeys(hostnames)) {
			// rare race condition can occur if a server submits metrics at the moment the summarize job starts
			this.logDebug(2 + sys.id);
			return process.nextTick( callback );
		}
		
		var contrib_key = 'contrib/' + sys.id + '/' + Tools.sub( sys.date_format, dargs );
		var update_data = null;
		var new_record = false;
		
		async.series(
			[
				function(callback) {
					// first, load last list item to see if epoch_div matches
					self.storage.get( contrib_key, function(err, data) {
						if (err || !data) new_record = true;
						update_data = data || { hostnames: {} };
						callback();
					});
				},
				function(callback) {
					// merge in new hostnames and save
					var num_additions = 0;
					for (var hostname in hostnames) {
						if (!(hostname in update_data.hostnames)) num_additions++;
					}
					if (num_additions || new_record) {
						Tools.mergeHashInto( update_data.hostnames, hostnames );
						self.storage.put( contrib_key, update_data, callback );
					}
					else process.nextTick( callback );
				},
				function(callback) {
					// possibly set expiration if new record
					if (new_record && self.server.config.get('expiration')) {
						// we just created the record, so set its expiration date
						var exp_date = Tools.timeNow() + Tools.getSecondsFromText( self.server.config.get('expiration') );
						self.storage.expire( contrib_key, exp_date );
					}
					process.nextTick( callback );
				}
			],
			callback
		); // async.series
	},
	
	monitorSelf: function() {
		if (!this.server.config.get('monitor_self')) return;
		
		var cli_args = [
		
			'--config', Path.resolve( 'conf/config.json' ),
			'--host', 'localhost:' + this.web.config.get('http_port'),
			'--enabled'
		];
		var node_bin = process.argv[0];
		
		this.logDebug(9, "Spawning satellite as detached process to collect local metrics", {
			node_bin: node_bin,
			cli_args: cli_args
		});
		
		// spawn child
		var child_opts = {
			cwd: process.cwd(),
			detached: true,
			env: Tools.mergeHashes( process.env, {
				'PATH': process.env['PATH'] + ':/usr/bin:/bin:/usr/local/bin:/usr/sbin:/sbin:/usr/local/sbin'
			} ),
			stdio: ['ignore', 'ignore', 'ignore']
		};
		
		try {
			child = cp.spawn( node_bin, cli_args, child_opts );
		}
		catch (err) {
			this.logError( "Child process error: " + Tools.getErrorDescription(err));
			return;
		}
		
		this.logDebug(9, "Spawned process: " + child.pid);
		child.unref();
	},
	
	tick: function() {
		// called every second
		var self = this;
		var now = Tools.timeNow(true);
		
		if (this.numSocketClients) {
			var status = {
				epoch: Tools.timeNow()
			};
			
			this.authSocketEmit( 'status', status );
		}
	},
	
	beforeUserLogin: function(args, callback) {
		// infuse data into user login client response
		var self = this;
		
		args.resp = {
			epoch: Tools.timeNow()
		};
		
		callback();
	},
	
	afterUserLogin: function(args) {
		// user has logged in
		this.logActivity('user_login', this.getClientInfo(args, { 
			user: Tools.copyHashRemoveKeys( args.user, { password: 1, salt: 1 } )
		}));
	},
	
	beforeUserChange: function(args, callback) {
		// clean up user full name and nickname
		var self = this;
		callback();
	},
	
	afterUserChange: function(action, args) {
		// user data has changed
		var username = args.user.username; // username cannot change
		
		// add to activity log in the background
		this.logActivity(action, this.getClientInfo(args, { 
			user: Tools.copyHashRemoveKeys( args.user, { password: 1, salt: 1 } )
		}));
	},
	
	runMaintenance: function() {
		// run routine daily tasks, called after storage maint completes.
		var self = this;
		var timeline_key = 'timeline/overview';
		
		// don't run this if shutting down
		if (this.server.shut) return;
		
		this.logDebug(4, "Beginning run");
		
		// delete old timeline data (for overview timeline)
		var max_len = Math.floor( Tools.getSecondsFromText( self.server.config.get('expiration') ) / 60 );
		
		this.storage.listGetInfo( timeline_key, function(err, list) {
			if (err) {
				self.logError('maint', "Failed ist: " + timeline_key + ": " + err + ", skipping maintenance");
			}
			if (list && list.length && (list.length > max_len)) {
				var num_to_remove = list.length - max_len;
				self.logDebug(4, "Performing maintenance on list: " + timeline_key, { list: list, num_to_remove: num_to_remove });
				
				self.storage.listSplice( timeline_key, 0, num_to_remove, [], function(err) {
					if (err) {
						return self.logError('maint', "Failed to splice list: " + timeline_key + ": " + err);
					}
					self.chopLists();
				}); // listSplice
			} // need chop
			else {
				self.logDebug(4, "No required on " + timeline_key + ", moving to next set");
				self.chopLists();
			}
		}); // listGetInfo
	},
	
	chopLists: function() {
		// chop long lists (part of daily maint)
		var self = this;
		var max_rows = this.server.config.get('list_row_max') || 0;
		if (!max_rows) {
			this.logDebug(4, "Maintenance complete");
			return;
		}
		
		var list_paths = ['logs/activity', 'logs/snapshots'];
		this.logDebug(4, "Continuing maintenance on lists", list_paths);
		
		async.eachSeries( list_paths, 
			function(list_path, callback) {
				// iterator function
				self.logDebug(4, "Working on list: " + list_path);
				
				self.storage.listGetInfo( list_path, function(err, info) {
					// list may not exist, skip if so
					if (err) {
						self.logError('maint', "Maintenance Error: " + err + " (skipping list: " + list_path + ")");
						return callback();
					}
					if (info.length > max_rows) {
						// list has grown too long, needs a trim
						self.logDebug(3, "List " + list_path + " has grown too long, trimming to max: " + max_rows, info);
						self.storage.listSplice( list_path, max_rows, info.length - max_rows, null, callback );
					}
					else {
						self.logDebug(4, "List is within limits, no maint required: " + list_path, info);
						callback();
					}
				} ); 
			}, // iterator
			function(err) {
				if (err) {
					self.logError('maint', "lists: " + err);
				}
			}
		); 
	},
	
	archiveLogs: function() {
		var self = this;
		var src_spec = this.server.config.get('log_dir') + '/*.log';
		
		if (this.server.config.get('log_archive_path')) {
			// archive to filesystem (not storage)
			var dest_path = this.server.config.get('log_archive_path');
			this.logDebug(4, "Archiving logs: " + src_spec + " to: " + dest_path);
			
			// generate time label from previous day, so just subtracting 30 minutes to be safe
			var epoch = Tools.timeNow(true) - 1800;
			
			this.logger.archive(src_spec, dest_path, epoch, function(err) {
				if (err) self.logError('maint', "Failed to archive logs: " + err);
				else self.logDebug(4, "Log archival complete");
			});
			
			return;
		}
	
			delete hook_args.description;
			hook_args.text = this.server.config.getPath('client/name') + ": " + hook_args.text;
			this.logDebug(9, "Firing web hook for " + action + ": " + web_hook_url);
			this.request.json( web_hook_url, hook_args, function(err, resp, data) {
				// log response
				if (err) self.logDebug(9, "Web Error: " + web_hook_url + ": " + err);
				else self.logDebug(9, "Web Response: " + web_hook_url + ": HTTP " + resp.statusCode + " " + resp.statusMessage);
			} );
		}
	},
	
	logTransaction: function(code, msg, data) {
		// proxy request to system logger with correct component for dedi trans log
		this.logger.set( 'component', 'Transaction' );
		this.logger.transaction( code, msg, data );
		
		if (!data) data = {};
		if (!data.description) data.description = msg;
		this.logActivity(code, data);
	},
	
	shutdown: function(callback) {
		// shutdown sequence
		var self = this;
		this.shut = true;
		this.logDebug(2, "System down");
		callback();
	});
