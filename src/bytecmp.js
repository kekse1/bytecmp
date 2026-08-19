#!/usr/bin/env node

/*
 * Copyright (c) Sebastian Kucharczyk <kuchen@kekse.biz>
 * https://kekse.biz/ https://github.com/kekse1/bytecmp/
 */

//
//TODO/WICHTIG!!1 am ende noch ausgabe *aller* duplicates
//		bzw. anzahl solcher dateien oder so.. in total!1
//
//TODO/am besten noch ein CUT der pfade...
//	... falls terminal-width zu klein.
//

//
const
	NAME = 'bytecmp',
	VERSION = '0.9.11';

//
const
	DEFAULT_BUFFER = (1024 * 256),
	DEFAULT_REGEXP = new RegExp(),
	DEFAULT_HASH = 'sha3-256',
	DEFAULT_DIGEST = 'base64',
	DEFAULT_RELATIVE = true,
	DEFAULT_VERBOSE = false,
	DEFAULT_SYMLINKS = true,
	DEFAULT_HIDDEN = false,
	DEFAULT_REFRESH = 220,
	DEFAULT_EMPTY = false,
	DEFAULT_DEPTH_MIN = 0,
	DEFAULT_DEPTH_MAX = 0,
	DEFAULT_SIZE_MIN = 0,
	DEFAULT_SIZE_MAX = 0,
	DEFAULT_BASE = 1024,
	DEFAULT_ANSI = true,
	DEFAULT_BIG = false,
	DEFAULT_OFFSET = 0,
	DEFAULT_ASYNC = 16,
	DEFAULT_GLOB = '*',
	DEFAULT_SIZE = 0,
	DEFAULT_PREC = 2;

//
import * as globals from '../shared/globals.js';
import * as server from '../shared/server.js';
import getopt from '../shared/getopt.js';
import crypt from '../shared/crypt.js';
import glob from '../shared/glob.js';
import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';

//
const PARAM = {
	'hidden': {
			'TYPE': 'boolean',
			'type': 'Boolean',
			'value': DEFAULT_HIDDEN,
			'description': 'Also find hidden (dot-)files?'
		},
	'ansi': {
			'TYPE': 'boolean',
			'type': 'Boolean',
			'value': DEFAULT_ANSI,
			'description': 'Maybe you oder your terminal don\'t like ANSI Escape Sequences (colors, etc.)?'
		},
	'refresh': {
			'TYPE': 'integer',
			'type': 'Integer[0..60000]',
			'value': DEFAULT_REFRESH,
			'description': 'If you don\'t want to see a progress bar, set it to zero(0)!'
		},
	'verbose': {
			'TYPE': 'boolean',
			'type': 'Boolean',
			'value': DEFAULT_VERBOSE,
			'description': 'Verbose output.. if you\'d like to find out more.'
		},
	'size': {
			'TYPE': [ 'integer', 'string' ],
			'type': [ 'Integer', 'String' ],
			'value': DEFAULT_SIZE,
			'description': 'Optional amount of bytes to read per file. Negative values will count from the end of file, zero will compare the whole files.'
		},
	'base': {
			'TYPE': 'integer',
			'type': 'Integer[1000,1024]',
			'value': DEFAULT_BASE,
			'description': 'The base of all sizes (1000 or 1024)'
		},
	'precision': {
			'TYPE': 'integer',
			'type': 'Integer[0..16]',
			'value': DEFAULT_PREC,
			'description': 'The floating point precision of all sizes.'
		},
	'empty': {
			'TYPE': 'boolean',
			'type': 'Boolean',
			'value': DEFAULT_EMPTY,
			'description': 'Also calculate the hash sums of EMPTY FILES?'
		},
	'offset': {
			'TYPE': [ 'integer', 'string' ],
			'type': [ 'Integer', 'String' ],
			'value': DEFAULT_OFFSET,
			'description': 'Begin to read laters, skipping some bytes (also from the end of file).'
		},
	'async': {
			'TYPE': 'integer',
			'type': 'Integer[1..]',
			'value': DEFAULT_ASYNC,
			'description': 'How many parallel (async) actions when reading files?'
		},
	'buffer': {
			'TYPE': [ 'integer', 'string' ],
			'type': [ 'Integer[1..]', 'String' ],
			'value': DEFAULT_BUFFER,
			'description': 'The buffer size when reading the files.'
		},
	'hash':  {
			'TYPE': 'string',
			'type': 'String',
			'value': DEFAULT_HASH,
			'description': 'See `--hashes` for a list!'
		},
	'hashes': {
			'TYPE': 'boolean',
			'type': 'Boolean',
			'value': false,
			'description': 'A list of any known hash type.'
		},
	'digest': {
			'TYPE': 'string',
			'type': 'String',
			'value': DEFAULT_DIGEST,
			'description': 'See `--digests` for a list!'
		},
	'digests': {
			'TYPE': 'boolean',
			'type': 'Boolean',
			'value': false,
			'description': 'A list of all valid digest types.'
		},
	'glob': {
			'TYPE': 'string',
			'type': 'String',
			'value': DEFAULT_GLOB,
			'description': 'Maybe useful when we\'re searching for files.'
		},
	'regexp': {
			'TYPE': 'string',
			'type': 'RegExp',
			'value': DEFAULT_REGEXP,
			'description': 'Similar to `--glob`, for searching files.'
		},
	'help': {
			'TYPE': 'boolean',
			'type': 'Boolean',
			'value': false,
			'description': 'Some more inf0 about this parameters, etc..'
		},
	'depth-min': {
			'TYPE': 'integer',
			'type': 'Integer[-1..]',
			'value': DEFAULT_DEPTH_MIN,
			'description': 'Minimum traverse depth; (-1) disables any limit.'
		},
	'depth-max': {
			'TYPE': 'integer',
			'type': 'Integer[-1..]',
			'value': DEFAULT_DEPTH_MAX,
			'description': 'Maximum traverse depth; (-1) disables any limit.'
		},
	'relative': {
			'TYPE': [ 'boolean', 'path' ],
			'type': [ 'Boolean', 'Path' ],
			'value': DEFAULT_RELATIVE,
			'description': 'Affects the resolving of path names in the output.'
		},
	'size-min': {
			'TYPE': [ 'integer', 'string' ],
			'type': [ 'Integer[0..]', 'String' ],
			'value': DEFAULT_SIZE_MIN,
			'description': 'Zero(0) disables this limit.'
		},
	'size-max': {
			'TYPE': [ 'integer', 'string' ],
			'type': [ 'Integer[0..]', 'String' ],
			'value': DEFAULT_SIZE_MAX,
			'description': 'Zero(0) disables this limit.'
		},
	'symlinks': {
			'TYPE': 'boolean',
			'type': 'Boolean',
			'value': DEFAULT_SYMLINKS,
			'description': 'Whether to follow symbolic links, or silently ignore them.'
		}
};

if(bool(PARAM.ansi.value))
{
	console.ansi = PARAM.ansi.value;
}

//
const KEYS = Object.keys(PARAM).sort(true);

//
const mathSize = (_bytes, _style = true) => Math.size(
	_bytes, PARAM['base'],
	PARAM['precision'],
	false, _style);

const printPath = (_path, _relative = PARAM['relative']) => {
	if(_relative === null)
	{
		_relative = PARAM['relative'];
	}
	
	if(bool(_relative))
	{
		_relative = (_relative ? process.cwd() : null);
	}
	else if(!global.path(_relative))
	{
		_relative = null;
	}
	
	if(_relative)
	{
		return path.relative(
			_relative, _path);
	}
	
	return _path;
};

const hashes = (_show = false) => {
	const result = crypt.hash;
	
	if(_show)
	{
		console.info('These are the possible ' +
			'hashes'.bold(true) + ':' + EOL);
		
		for(const item of result)
		{
			console.log('\t' + item);
		}
		
		console.eol();
	}
	
	return result;
};

const digests = (_show = false) => {
	const result = crypt.digest;
	
	if(_show)
	{
		console.info('These are the possible ' +
			'digests'.bold(true) + ':' + EOL);
		
		for(const item of result)
		{
			console.log('\t' + item);
		}
		
		console.eol();
	}
	
	return result;
};

const help = (_exit = 0) => {
	//
	if(bool(_exit))
	{
		_exit = (_exit ? Math.random.
			byte(255, 1) : 0);
	}
	else if(int(_exit))
	{
		_exit = Math.abs(_exit % 256);
	}
	else
	{
		_exit = null;
	}

	//
	const HELP = help.prepare(_exit);
	const DESC = (HELP.max.pre + (3 * 2));
	const write = (_eol = 0, _string = '') => {
		const string = (_string + eol(_eol || 0));
		HELP.stream.write(string + String.none());
		return string.text.length };

	for(const line of HELP.head)
	{
		write(1, line);
	}

	var len, desc; for(const key of KEYS)
	{
		len = write(0, '  --' + key.padEnd(HELP.max.key, ' ').info(true)
			+ '  ' + PARAM[key].type.padStart(HELP.max.type, ' ').
			error(true) + '  ' + PARAM[key].default.padEnd(
			HELP.max.default, ' ').warn(true));

		if(PARAM[key].description && len < HELP.width)
		{
			len += write(0, '  ');
			desc = PARAM[key].description;
			
			for(var i = 0; i < desc.length; ++i)
			{
				if(len >= HELP.width)
				{
					write(1);
					len = write(0, ''.padStart(DESC, ' '));
					//len = write(0, ' '.repeat(DESC));
					
					while(desc[i] === ' ' || desc[i] === '\t')
					{
						++i;
					}
					
					len += write(0, '\t');
				}
				
				len += write(0, desc[i].debug(true));
			}
			
			if(DEFAULT_BIG)
			{
				write(1);
			}
		}
		
		write(1);
	}

	write(1);
	
	//
	if(_exit !== null)
	{
		process.exit(_exit);
	}
};

help.prepare = (_exit) => {
	const stream = (_exit ? process.stderr : process.stdout);
	const result = { stream, width: (stream.columns || 24),
		max: { key: 0, type: 0, default: 0, description: 0 },
		head: help.prepare.header(), tab: String.TAB.length };

	var len; for(const idx in PARAM)
	{
		if((len = (PARAM[idx].key = ('--' + idx)).
				length) > result.max.key)
		{
			result.max.key = len;
		}

		if((len = (PARAM[idx].type = help.prepare.type(
				PARAM[idx].type)).length) > result.max.type)
		{
			result.max.type = len;
		}

		if((len = (PARAM[idx].default = String.render(PARAM[idx].value)).length) > result.max.default)
		{
			result.max.default = len;
		}

		if((len = PARAM[idx].description.length) > result.max.description)
		{
			result.max.description = len;
		}
	}
	
	result.max.pre = result.max.key + result.max.type + result.max.default;
	return result;
};

help.prepare.type = (_item) => {
	if(string(_item))
	{
		return _item;
	}

	return _item.join(' / ');
};

help.prepare.header = () => [
	'', '\t`' + NAME.bold() + String.none() +
	'`\tv' + VERSION, '\t\tCopyright (c) Sebastian ' +
	'Kucharczyk <kuchen@kekse.biz>', '',
	'  Syntax: ' + path.basename(process.argv[1]) +
		' < path [ ... ] > [ ... param ]', '' ];

//
const param = getopt({
	array: false,
	unescape: true,
	castRegular: false,
	equalAssign: true,
	regexp: false,
	cast: true });

if(param.has('--ansi'), 'boolean')
{
	console.ansi = param.get('--ansi');
}

if(param.help)
{
	PARAM.help.value = true;
	help(0);
}
else if(param.get('hashes'))
{
	hashes(true);
	process.exit();
}
else if(param.get('digests'))
{
	digests(true);
	process.exit();
}
else if(param.length === 0)
{
	param.push(process.cwd());
}

var check;

if((check = param.checkKeys(KEYS, false)).length > 0)
{
	console.error('Invalid getopt key' + (check.length === 1 ? '' : 's') + ':' + EOL);
	
	for(const item of check)
	{
		console.error('\t' + item.warn());
	}
	
	console.debug(EOL + 'Use --help/-? for some help.');
	process.exit(254);
}

check = new Map();

for(const item of KEYS)
{
	check.set(item, PARAM[item].TYPE);
}

if((check = param.checkValues(check, false, false)).length > 0)
{
	console.error('Invalid getopt parameter to following key' + (check.length === 1 ? '' : 's') + ':' + EOL);
	
	for(const item of check)
	{
		console.error('\t' + item.warn());
	}
	
	console.debug(EOL + 'Use --help/-? for some help.');
	process.exit(253);
}

for(const key of param.keys)
{
	PARAM[key.substr(2)].value = param.get(key);
}

for(const idx in PARAM)
{
	switch(idx)
	{
		case 'size':
		case 'size-min':
		case 'size-max':
		case 'offset':
		case 'buffer':
			if(string(PARAM[idx].value, false))
			{
				if((PARAM[idx].value = Math.size.parse(
					PARAM[idx].value)) === null)
				{
					console.error('Invalid parameter for getopt key `--' +
						idx + '` (unable to parse String)!');
					process.exit(1);
				}
			}
			break;
		case 'regexp':
			if(PARAM['regexp'].value && (PARAM[idx].value = RegExp.parse(PARAM[idx].value)) === null)
			{
				console.error('Invalid value for getopt key `--' + idx + '`, ' +
					'is not a valid RegExp (Regular Expression)!');
				process.exit(2);
			}
			break;
	}
	
	PARAM[idx] = PARAM[idx].value;
}

const HASH = hashes(false);
const DIGEST = digests(false);

for(const key in PARAM) switch(key)
{
	case 'async':
	case 'buffer':
		if(PARAM[key] < 1)
		{
			console.error('The `--' + key + '` needs to be greater than zero(0).');
			process.exit(3);
		}
		break;
	case 'offset':
		if(PARAM[key] < 0)
		{
			console.error('The `--offset` needs to be a positive Integer.');
			process.exit(4);
		}
		break;
	case 'digest':
		if(!DIGEST.includes(PARAM[key]))
		{
			console.error('Invalid `--digest`; .. see `--digests`!');
			process.exit(5);
		}
		break;
	case 'hash':
		if(!HASH.includes(PARAM[key]))
		{
			console.error('Invalid `--hash`; .. see `--hashes`!');
			process.exit(6);
		}
		break;
	case 'size':
		if(PARAM['size'] && (PARAM['size-min'] || PARAM['size-max']))
		{
			console.error('The `--size` may not be used with `--size-max` and/or `--size-min`.');
			process.exit(7);
		}
		break;
	case 'size-max':
	case 'size-min':
		if(PARAM['size'] && (PARAM['size-max'] || PARAM['size-min']))
		{
			console.error('The `--size-max` and/or `--size-min` may not be used with `--size`.');
			process.exit(8);
		}
		
		if(PARAM[key] < 0)
		{
			console.error('The `--' + key + '` needs to be at least zero(0).');
			process.exit(9);
		}
		break;
	case 'depth-max':
	case 'depth-min':
		if(PARAM[key] < -1)
		{
			console.error('The `--' + key + '` needs to be at least (-1).');
			process.exit(10);
		}
		break;
	case 'base':
		switch(PARAM[key])
		{
			case 1000:
			case 1024:
				break;
			default:
				console.error('The `--base` needs to be either (1000) or (1024)!');
				process.exit(11);
				break;
		}
		break;
	case 'precision':
		if(PARAM[key] < 0 || PARAM[key] > 16)
		{
			console.error('Your `--precision` needs to be an Integer [ 0 .. 16 ].');
			process.exit(12);
		}
		break;
}

if(PARAM['depth-max'] > 0 && PARAM['depth-min'] > 0)
{
	if(PARAM['depth-max'] < PARAM['depth-min'])
	{
		console.error('The `--depth-max` needs to be greater or equal to `--depth-min`.');
		process.exit(13);
	}
}

//
var ignored = 0;

const checkFilterLimits = (_item, _index = 0) => {
	if(PARAM['glob'] && !_item.name[_index].glob(PARAM['glob']))
	{
		return false;
	}
	
	if(PARAM['regexp'] && !PARAM['regexp'].test(_item.name[_index]))
	{
		return false;
	}
	
	if(PARAM['size'] && _item.size <= (Math.abs(PARAM['size']) + PARAM['offset']))
	{
		return false;
	}
	
	if(PARAM['size-min'] > 0 && _item.size < PARAM['size-min'])
	{
		return false;
	}
	
	if(PARAM['size-max'] > 0 && _item.size >= PARAM['size-max'])
	{
		return false;
	}
	
	if(PARAM['offset'] && PARAM['offset'] >= _item.size)
	{
		return false;
	}
	
	return true;
};

const	FILES = new Map();
var	totalFiles = 0,
	totalLinks = 0,
	totalSize = 0,
	doneSize = 0,
	todoSize,
	arr;

const filterFile = (_path, _item) => {
	var item = fs.statSync(_path, {
		throwIfNoEntry: false,
		bigInt: false });

	if(!item || !item.isFile())
	{
		return null;
	}
	
	try
	{
		item.real = fs.realpathSync(_path =
			path.resolve(_path));
	}
	catch(_err)
	{
		++ignored;
		return null;
	}

	if(FILES.has(item.real))
	{
		item = Object.assign(FILES.
			get(item.real), item);
	}

	if(array(item.path, true))
	{
		item.path.push(_path = path.resolve(_path));
	}
	else
	{
		item.path = [ _path = path.resolve(_path) ];
	}

	if(array(item.name, true))
	{
		item.name.push(_item.name);
	}
	else
	{
		item.name = [ _item.name ];
	}

	if(!item.path.includes(item.real))
	{
		item.path.unshift(item.real);
		item.name.unshift(item.name);
	}

	if(!checkFilterLimits(item, item.path.length - 1))
	{
		++ignored;
		return null;
	}

	if(_path !== item.real)
	{
		if(!PARAM['symlinks'])
		{
			return null;
		}
		
		++totalLinks;
	}
	else
	{
		++totalFiles;
	}

	FILES.set(item.real, item);
	return item;
};

const prepareStreaming = (_item) => {
	_item.hash = crypto.createHash(PARAM['hash']);
	_item.offset = PARAM['offset'];
	_item.options = {};
	
	if(PARAM['size'])
	{
		if(PARAM['size'] > 0)
		{
			_item.options.start = _item.offset;
			_item.options.end = (_item.options.start +
						PARAM['size'] - 1);
		}
		else
		{
			_item.options.start = (_item.size - 1
				+ PARAM['size'] - _item.offset);
			_item.options.end = (_item.options.start +
				Math.abs(PARAM['size']));
		}

		_item.bytes = Math.abs(PARAM['size']);
	}
	else
	{
		_item.bytes = (_item.size - PARAM['offset']);
	}

	if(_item.path.length === 1)
	{
		totalSize += _item.bytes;
	}

	_item.done = 0;
	_item.todo = _item.bytes;

	Object.assign(_item.options, {
		encoding: null,
		autoClose: true,
		emitClose: true,
		highWaterMark: PARAM['buffer']
	});

	return _item;
};

var maxDepth = 0; const traverse = (_depth = 0, ... _path) => {
	maxDepth = Math.max(maxDepth, _depth);
	const list = fs.readdirSync(_path.join(path.sep), {
		encoding: 'utf8', withFileTypes: true });

	for(var i = 0; i < list.length; ++i)
	{
		if(list[i].name[0] === '.' && !PARAM['hidden'])
		{
			continue;
		}

		const subPath = list[i].path = path.join(
			_path.join(path.sep), list[i].name);

		if(list[i].isSymbolicLink())
		{
			if(!PARAM['symlinks'])
			{
				continue;
			}
		}

		if(list[i].isDirectory())
		{
			if(PARAM['depth-max'] < 0 || _depth < PARAM['depth-max'])
			{
				traverse(_depth + 1, subPath);
			}
			else if(_depth < PARAM['depth-min'])
			{
				traverse(_depth + 1, subPath);
			}
		}
		else if((list[i].isFile() || list[i].isSymbolicLink()) &&
			(PARAM['depth-min'] < 0 || _depth >= PARAM['depth-min']))
		{
			if(list[i] = filterFile(subPath, list[i]))
			{
				prepareStreaming(list[i]);
			}
		}
		else
		{
			++ignored;
		}
	}
};

for(var i = 0, p = 0; i < param.length; ++i)
{
	if(global.path(param[i]) && fs.existsSync(param[i]))
	{
		const stat = fs.statSync(param[i], {
			throwIfNoEntry: false,
			bigint: false });

		if(stat)
		{
			Object.assign(stat, {
				path: path.resolve(param[i]),
				real: fs.realpathSync(param[i]),
				name: path.basename(param[i]) });

			if(stat.isFile())
			{
				const item = filterFile(param[i], stat);
				
				if(item)
				{
					prepareStreaming(item);
				}
			}
			else if(stat.isDirectory())
			{
				traverse(0, ... param[i].
					split(path.sep));
			}
			else
			{
				++ignored;
			}
		}
		else
		{
			++ignored;
		}
	}
	else
	{
		++ignored;
	}
}

for(const item of FILES)
{
	if(item[1].hasSymbolicLinks = (item[1].path.length > 1))
	{
		for(var i = 0; i < item[1].path.length; ++i)
		{
			if(item[1].path[i] === item[1].real)
			{
				item[1].path.unshift(
					item[1].path.splice(
						i, 1)[0]);
				item[1].name.unshift(
					item[1].name.splice(
						i, 1)[0]);
				break;
			}
		}
	}
}

//
if(ignored)
{
	console.warn('We ignored ' + ignored.toLocaleString().error() +
		' filesystem entr' + (ignored === 1 ? 'y' : 'ies') + (' (out of ' +
		'your ' + param.length.toLocaleString().warn() + ' parameter' +
		(param.length === 1 ? '' : 's') + ').').debug());
}

const total = (totalFiles + totalLinks);

if(FILES.size === 0)
{
	console.error('No files left after searching/filtering ... so we ' +
		'need to stop'.warn().bold(true) + ' here!');
	process.exit(14);
}
else
{
	todoSize = totalSize;

	console.info('Found ' + total.toLocaleString().error() +
		' entr' + (FILES.size === 1 ? 'y' : 'ies') +
		(' (which weren\'t filtered out)').debug() + '.'.info());
	if(totalLinks) console.debug('Whereas ' + totalLinks.
		toLocaleString().info() + ' of them ' + (totalLinks === 1 ?
		'is a symbolic link' : 'are symbolic links') +
		(' (so ' + totalFiles.toLocaleString().info() +
		' are real files)').error() + '.'.debug());
	console.warn('The effective size we have to process is ' +
		mathSize(totalSize).info() + (' (' + totalSize.
		toLocaleString() + ' Bytes)').debug() + '.'.warn());
}

//
if(PARAM['verbose'])
{
	console.info(EOL + 'Here\'s a list of all files ' + ('(.. you enabled `' +
		'--verbose'.warn() + '`)').debug() + ':'.info());
	if(maxDepth) console.debug('We traversed into a maximum directory depth of ' +
		maxDepth.toLocaleString().info() + '.'.debug());
	console.eol();
	
	for(const item of FILES)
	{
		const p = [ ... item[1].path ];
		console.error('\t' + printPath(p.shift()));
		
		for(const pp of p)
		{
			console.error('\t' + printPath(pp) +
				' => '.warn() + printPath(
					item[0]).info());
		}
	}
	
	console.eol();
}

//
String.RESET = false;

var	done, todo,
	timeout = null,
	baseLineLength,
	active;
const	maxSizeLen = (mathSize(
		totalSize, false).length + 6),
	maxPercentLen = (PARAM['precision'] + 5);

//
const getPercentString = () => {
	var factor = (doneSize / totalSize);
	factor = Math.min(1, factor);
	factor = Math.max(0, factor);
	const percent = (factor * 100).
		toFixed(PARAM['precision']).split('.');
	percent[0] = percent[0].bold(true);
	var result = percent.join('.').fg(200, 230, 40);
	result += '%'.fg(150, 220, 230) + String.none();
	return result.pad(maxPercentLen, ' ', true);
};

const drawProgressBar = (_bytes = doneSize) => {
	if(!process.progressBar)
	{
		return 0;
	}
	
	const width = process.progressBar.columns;

	if(width <= 0)
	{
		return process.progressBar.write('\r');
	}	
	
	var line = ('  ' + mathSize(_bytes, true).fg(230, 190, 10).
		pad(maxSizeLen, ' ', true) + ' / '.debug() +
		mathSize(totalSize, true).fg(160, 190, 220).pad(
		-maxSizeLen, ' ', true)) + getPercentString();
	baseLineLength = line.text.length;
	
	if(baseLineLength >= width)
	{
		return process.progressBar.write('\r' +
			((line + String.none()).
			pad(-width, ' ', true)).
			substr(0, width));
	}
	
	baseLineLength += 3;
	line += ' ' + '('.fg(220, 255, 0).bold(true);

	done = Math.round(_bytes / totalSize * (width - baseLineLength));
	todo = (width - done - baseLineLength);
	line += '/'.repeat(done).fg(230, 200, 60);
	line += '-'.repeat(todo).fg(90, 160, 170);
	
	line += ')'.fg(220, 255, 0).bold(true) + String.none();

	if(active && !timeout) timeout = setTimeout(() => {
		timeout = null; drawProgressBar(); },
			PARAM['refresh']);

	return process.progressBar.write(
		'\r' + line + String.none());
};

//
const	QUEUE = [ ... FILES.values() ],
	ERROR = [],
	OPEN = [];
var	RESULT = new Map();

const checkQueue = () => {
	var result = 0;
	
	if(QUEUE.length === 0 && OPEN.length === 0 && (_CODE === null && !_SIGINT))
	{
		setImmediate(onFinish);
		return result;
	}
	
	while(QUEUE.length > 0 && OPEN.length < PARAM['async'])
	{
		fileHandler(QUEUE.shift());
		++result;
	}
	
	return result;
};

const fileHandler = (_item) => {
	_item.hash = crypto.createHash(PARAM['hash']);
	_item.stream = fs.createReadStream(
		_item.real, _item.options);

	var isFinished = false;

	_item.stream.once('close', () => {
		OPEN.remove(_item);

		if(isFinished)
		{
			_item.hash = _item.hash.digest(PARAM['digest']);

			if(RESULT.has(_item.hash))
			{
				RESULT.get(_item.hash).push(_item);
			}
			else
			{
				RESULT.set(_item.hash, [ _item ]);
			}
		}
		else
		{
			_item.hash = null;
		}

		if(OPEN.length === 0 && (_SIGINT || _CODE !== null))
		{
			onDestroyed();
		}
		else
		{
			setImmediate(checkQueue);
		}
	});
	
	_item.stream.once('error', (_e) => {
		if(_e.name !== 'AbortError')
		{
			ERROR.pushUnique(_item.real);
		}
		
		if(isFinished === false)
		{
			isFinished = null;
		}
	});
	
	_item.stream.once('end',
		() => isFinished = true);

	_item.stream.on('data', (_chunk) => {
		if(_chunk.length > _item.bytes)
		{
			_chunk = _chunk.subarray(
				0, _item.todo);
		}

		_item.hash.update(_chunk);
		
		doneSize += _chunk.length;
		todoSize -= _chunk.length;
		
		_item.done += _chunk.length;
		_item.todo -= _chunk.length;
		
		if(_item.todo <= 0)
		{
			isFinished = true;

			_item.stream.pause();
			_item.stream.destroy();
		}
	});
	
	return OPEN.push(_item);
};

//
var CURSOR = true;
	const cursor = (_enabled = !CURSOR) => {
		if(_enabled === CURSOR) return false;
		console.getTTY(false).write(String[(_enabled ?
			'show' : 'hide') + 'Cursor']());
		CURSOR = _enabled; return true; };

const startProcess = () => {
	process.once('SIGINT', () => stopProcess(130, null, true));
	process.once('exit', () => stopProcess(null));
	cursor(false); if(!PARAM['verbose']) console.eol();
	
	if(PARAM['refresh'] && (process.progressBar = console.getTTY(false)))
	{
		active = true;
		drawProgressBar();
	}
	else
	{
		active = null;
		process.progressBar = null;
		process.stdin.pause();
	}
	
	return setImmediate(checkQueue);
};

var	_HAS = false,
	_CODE = null,
	_SIGINT = false,
	_TIMEOUT = null;

const _stopProcess = () => setImmediate(() => {
	if(_HAS) throw new Error('Unexpected');
	_HAS = true; cursor(true); active = false;
	var text;
	
	if(_SIGINT)
	{
		console.log(' SIGINT'.fg(220, 180, 40) +
			'!'.fg(255, 0, 0) + String.none());
		_CODE = 130;
	}

	if(_SIGINT) process.kill(process.pid, 'SIGINT');
	else console.log(); process.exit(_CODE || 0);
});

const stopProcess = (_code = 0, _timeout = null, _sigint = false) => {
	cursor(true);
	
	if(_code === null)
	{
		return;
	}
	
	if(_SIGINT = _sigint)
	{
		_CODE = _code = 130;
	}
	else
	{
		_CODE = (_code || 0);
	}

	if(int(_timeout))
	{
		setTimeout(_stopProcess, _timeout);
	}
	else
	{
		_stopProcess();
	}
};

const onDestroyed =
	() => _stopProcess();

var calledFinish = false; const onFinish = () => setImmediate(() => {
	if(calledFinish)
	{
		//throw new Error('Unexpected');
		return false;
	}
	
	calledFinish = true;

	if(process.progressBar)
	{
		drawProgressBar(totalSize);
		process.progressBar = null;
		console.eol(2);
	}

	if(RESULT.size === 0)
	{
		console.error('I was ' + 'not able'.underline(true) +
			' to create ' + 'any'.bold(true) + ' hash sum!');
	}

	if(ERROR.length > 0)
	{
		console.error(ERROR.length.toLocaleString().warn() + ' errors occured when ' +
			'trying to read your ' + total.toLocaleString().info() + ' file' +
			(total === 1 ? '' : 's') + '.'.debug());
		
		if(PARAM['verbose'])
		{
			console.warn('These files caused errors:' + EOL);
			
			for(const err of ERROR)
			{
				console.debug('\t' + printPath(err));
			}
			
			console.eol();
		}
	}

	if(QUEUE.length > 0)
	{
		console.log('This Job didn\'t finish work ('.warn() + QUEUE.length.
			toLocaleString().info() + ' items left)'.error() + '!'.warn());
	}

	if(RESULT.size === 0)
	{
		return process.exit(160);
	}

	RESULT = new Set([ ... RESULT ].
		sort('1.length', false));

	console.info('Successfully created ' + RESULT.size.toLocaleString().
		error() + ' hash sums '.bold(true) + '('.info() + PARAM['hash'].
		fg(150, 40, 190) + '/' + PARAM['digest'].
		fg(190, 40, 120) + ')!'.info());
	console.eol();

	var	duplicates = 0,
		symlinks = 0;

	for(const item of RESULT)
	{
		duplicates += (item[1].length - 1);
		
		for(const sub of item[1])
		{
			if(sub.path.length > 1 && PARAM['symlinks'])
			{
				symlinks += (sub.path.length - 1);
			}
		}
	}

	const results = (duplicates + symlinks);

	if(results === 0 && !PARAM['verbose'])
	{
		console.info(('\tNo duplicates'.bold(true) + ' found' + '!'.
			fg(255, 0, 0).bold(true)).underline(true) + EOL);
		if(!PARAM['symlinks']) console.debug('Maybe you\'d like to enable ' +
			'the `' + '--symlinks'.error() + '`?');
		console.debug('And maybe you want to enable the `' + '--verbose'.
			error() + '`?'.debug());
		process.exit();
	}
	else
	{
		console.debug('The following list is sorted by amount of duplicate ' +
			'files'.underline(true) + ', descending.');
	}

	console.eol();

	//
	for(const item of RESULT)
	{
		const values = [ ... item[1] ];
		const files = new Set();
		const links = new Set();
		
		for(const v of values)
		{
			files.add(v);
			
			for(var i = 1; i < v.path.length; ++i)
			{
				links.add(v.path[i]);
			}
		}
		
		if(links.size === 0 && files.size <= 1)
		{
			if(!PARAM['verbose'])
			{
				continue;
			}
		}

		console.eol();
		console.line('=');
		console.info('  ' + item[0].fg(0, 0, 0).bg(255, 255, 255));
		console.line('= ');
		console.eol();

		if(PARAM['symlinks'])
		{
			if(links.size === 0)
			{
				console.debug('No ' + 'symblic link'.underline(true) +
					' found for this file.' + EOL);
			}
			else
			{
				console.warn('Found ' + links.size.toLocaleString().error().bold(true) +
					' ' + ('symbolic link' + (links.size === 1 ? '' : 's')).info().
					underline(true) + (' (to this file ' + 'hash sum'.bold(true) +
					')').debug() + ':'.warn() + EOL);

				const printList = [];
				var maxLength = 0;
				
				for(const l of links)
				{
					printList.push(printPath(l));
					maxLength = Math.max(maxLength,
						printList[printList.length - 1].
							text.length);
				}
							
				for(const pli of printList)
				{
					console.info('\t' + printPath(pli));
				}
				
				console.eol();
			}
		}
		
		if(files.size === 0)
		{
			console.debug('This shouldn\'t happen... eh?!');
		}
		else
		{
			console.warn('Found ' + files.size.toLocaleString().error().bold(true) +
				' ' + ('file'.info() + (files.size === 1 ? '' : 's')).error().
				underline(true) + (' (with the same ' + 'hash sum'.bold(true) + ')').
				debug() + ':'.error() + EOL);
			
			const printList = [];
			var maxLength = 0;
			
			for(const f of files)
			{
				printList.push([ printPath(f.path[0]), f ]);
				maxLength = Math.max(maxLength,
					printList[printList.length - 1][0].
						text.length);
			}

			for(const pli of printList)
			{
				console.error('\t' + pli[0].pad(maxLength, ' ') + (' \t ' +
					mathSize(pli[1].size).warn() + (' / '.defaultFG(true) +
					pli[1].size.toLocaleString().bold(true) +
					' Bytes').debug()).info());
			}
			
			console.eol();
		}
	}

	stopProcess(0, null, false);
});

//
startProcess();

//
