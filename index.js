/*
  Copyright Jesús Pérez <jesusprubio@fsf.org>

  This code may only be used under the MIT license found at
  https://opensource.org/licenses/MIT.
*/

'use strict';

const net = require('net');

const cli = require('shodan-client');
const lodash = require('lodash');
const logger = require('pown-logger');
const validator = require('pown-validator');

let pkgName = require('./package').name;


// The huge timeout is because the API is really lazy.
const defaults = { query: 'freepbx', timeout: 20000, pages: 1 };
pkgName = pkgName.slice(5);


exports.yargs = {
  command: pkgName,
  describe: 'Query for hosts, IP address or exploits to Shodan.',

  builder: {
    key: {
      type: 'string',
      alias: 'k',
      describe: 'Your Shodan API key',
    },
    query: {
      type: 'string',
      alias: 'q',
      describe: 'If an IP address is passed I will look if it\'s indexed, in other case ' +
                'I will make a regular Shodan query, ie: "asterisk port:5060". Except ' +
                `if the "exploits" argument is also passed [${defaults.query}]`,
    },
    exploits: {
      type: 'boolean',
      alias: 'e',
      describe: 'Use the quer to search for exploits instead of hosts [false]',
    },
    pages: {
      type: 'number',
      alias: 'p',
      describe: 'Number of pages (of results) to return (only 1 allowed' +
                ` with free accounts) [${defaults.pages}]`,
    },
    timeout: {
      type: 'number',
      alias: 't',
      describe: `Request timeout [${defaults.timeout}]`,
    },
  },

  handler: (argv = {}) => {
    logger.title(pkgName);

    if (!argv.key) { throw new Error('The option "key" is mandatory'); }

    const query = argv.query || defaults.query;
    const timeout = argv.timeout || defaults.timeout;
    const page = argv.pages || defaults.pages;
    let queryPromise;

    if (argv.exploits) {
      queryPromise = cli.exploits.search(query, argv.key, { timeout, page });
    } else if (net.isIP(query)) {
      if (validator.isPrivateIp(query)) {
        logger.result('Private IP');

        return;
      }

      // We prefer to get all the records Shodan have about the host.
      queryPromise = cli.host(query, argv.key, { timeout, history: true });
    } else {
      queryPromise = cli.search(query, argv.key, { timeout, page });
    }

    queryPromise
    .then((res) => {
      if (res.total && res.matches) {
        logger.result('Total', res.total);
        logger.result('Matches');
        logger.chunks(res.matches, 1);
      } else if (res.data) {
        const trim = lodash.cloneDeep(res);
        delete trim.data;
        // We don't want to print the full data object.
        logger.result(null, trim);

        logger.result('History');
        logger.chunks(res.data, 1);
        // logger.chunks(res.data, 1);
      }
    });
  },
};
