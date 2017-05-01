'use strict';

// Load modules

const Boom = require('boom');
const Hoek = require('hoek');
const jwt  = require('jsonwebtoken');

// Declare internals

const internals = {};

exports.register  = function(server, options, next) {

    const pluginConfig = Hoek.clone(options);
    if (typeof pluginConfig.debug === 'undefined') {
        pluginConfig.debug = false;
    }

    server.ext('onPostAuth', function(request, reply)  {

        if (request._route.settings && request._route.settings.plugins && request._route.settings.plugins.cognito) {
            var routeConfig = request._route.settings.plugins.cognito;

            if (pluginConfig.debug) console.log("cognito authorization required");

            var decoded = jwt.decode(request.headers.authorization);
            if (decoded === null && (routeConfig.required || routeConfig.group || routeConfig.custom)) {
                console.error("cognito cannot decode jwt token");
                return reply(Boom.unauthorized(null, 'Cognito', null));
            }

            var credentials = {
                username: decoded['cognito:username'],
                firstName: decoded['given_name'],
                lastName: decoded['family_name'],
                email: decoded['email'],
                id: decoded['sub'],
                groups: decoded['cognito:groups'] ? decoded['cognito:groups'] : [],
                hasGroup: function(group) {
                    for (var i=0; i<credentials.groups.length; i++) {
                        if (group === credentials.groups[i]) {
                            return true;
                        }
                    }
                    return false;
                }
            };

            request.credentials = credentials;
            if (pluginConfig.debug) console.log("cognito credentials", credentials);

            if (routeConfig.group) {
                if (pluginConfig.debug) console.log("cognito group check", routeConfig.group, credentials.groups);
                if (credentials.hasGroup(routeConfig.group)) {
                    if (pluginConfig.debug) console.log("cognito group check success");
                    return reply.continue();
                } else {
                    if (pluginConfig.debug) console.log("cognito group check failed");
                    return reply(Boom.unauthorized(null, 'Cognito', null));
                }
            }

            var callback = function(result, message) {
                if (pluginConfig.debug) console.log("cognito custom callback", result, message);

                if (result) {
                    return reply.continue();
                } else {
                    return reply(Boom.forbidden(message));
                }
            };

            if (routeConfig.custom) {
                console.log("cognito custom strategy", typeof routeConfig.custom);
                if (typeof routeConfig.custom === 'function') {
                    if (pluginConfig.debug) console.log("cognito custom routeConfig function", result, message);
                    routeConfig.custom(request, credentials, callback);
                }
                else if (typeof routeConfig.custom === 'string') {
                    if (pluginConfig.debug) console.log("cognito custom pluginConfig function", routeConfig.custom);
                    var fcustom = pluginConfig.custom[routeConfig.custom];
                    if (fcustom === null) {
                        return reply(Boom.badImplementation("not configured correctly, custom authorizer "+routeConfig.custom+" not found"));
                    } else {
                        fcustom(request,credentials, callback);
                    }
                }
            } else {
                reply.continue();
            }
        } else {
            reply.continue();
        }
    });

    next();
};

exports.register.attributes = {
    pkg: require('../package.json')
};