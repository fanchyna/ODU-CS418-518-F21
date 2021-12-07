var hexcase = 0;
var b64pad  = "";  

function hex_md5(s)    { return rstr2hex(rstr_md5(str2rstr_utf8(s))); }
function b64_md5(s)    { return rstr2b64(rstr_md5(str2rstr_utf8(s))); }
function any_md5(s, e) { return rstr2any(rstr_md5(str2rstr_utf8(s)), e); }
function hex_hmac_md5(k, d)
  { return rstr2hex(rstr_hmac_md5(str2rstr_utf8(k), str2rstr_utf8(d))); }
function b64_hmac_md5(k, d)
  { return rstr2b64(rstr_hmac_md5(str2rstr_utf8(k), str2rstr_utf8(d))); }
function any_hmac_md5(k, d, e)
  { return rstr2any(rstr_hmac_md5(str2rstr_utf8(k), str2rstr_utf8(d)), e); }


function md5_vm_test()
{
  return hex_md5("abc").toLowerCase() == "900150983cd24fb0d6963f7d28e17f72";
}


function rstr_md5(s)
{
  return binl2rstr(binl_md5(rstr2binl(s), s.length * 8));
}

/*
 * Calculate the HMAC-MD5, of a key and some data (raw strings)
 */
function rstr_hmac_md5(key, data)
{
  var bkey = rstr2binl(key);
  if(bkey.length > 16) bkey = binl_md5(bkey, key.length * 8);

  var ipad = Array(16), opad = Array(16);
  for(var i = 0; i < 16; i++)
  {
    ipad[i] = bkey[i] ^ 0x36363636;
    opad[i] = bkey[i] ^ 0x5C5C5C5C;
  }

  var hash = binl_md5(ipad.concat(rstr2binl(data)), 512 + data.length * 8);
  return binl2rstr(binl_md5(opad.concat(hash), 512 + 128));
}

/*
 * Convert a raw string to a hex string
 */
function rstr2hex(input)
{
  try { hexcase } catch(e) { hexcase=0; }
  var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
  var output = "";
  var x;
  for(var i = 0; i < input.length; i++)
  {
    x = input.charCodeAt(i);
    output += hex_tab.charAt((x >>> 4) & 0x0F)
           +  hex_tab.charAt( x        & 0x0F);
  }
  return output;
}

/*
 * Convert a raw string to a base-64 string
 */
function rstr2b64(input)
{
  try { b64pad } catch(e) { b64pad=''; }
  var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var output = "";
  var len = input.length;
  for(var i = 0; i < len; i += 3)
  {
    var triplet = (input.charCodeAt(i) << 16)
                | (i + 1 < len ? input.charCodeAt(i+1) << 8 : 0)
                | (i + 2 < len ? input.charCodeAt(i+2)      : 0);
    for(var j = 0; j < 4; j++)
    {
      if(i * 8 + j * 6 > input.length * 8) output += b64pad;
      else output += tab.charAt((triplet >>> 6*(3-j)) & 0x3F);
    }
  }
  return output;
}

/*
 * Convert a raw string to an arbitrary string encoding
 */
function rstr2any(input, encoding)
{
  var divisor = encoding.length;
  var i, j, q, x, quotient;

  /* Convert to an array of 16-bit big-endian values, forming the dividend */
  var dividend = Array(Math.ceil(input.length / 2));
  for(i = 0; i < dividend.length; i++)
  {
    dividend[i] = (input.charCodeAt(i * 2) << 8) | input.charCodeAt(i * 2 + 1);
  }

  var full_length = Math.ceil(input.length * 8 /
                                    (Math.log(encoding.length) / Math.log(2)));
  var remainders = Array(full_length);
  for(j = 0; j < full_length; j++)
  {
    quotient = Array();
    x = 0;
    for(i = 0; i < dividend.length; i++)
    {
      x = (x << 16) + dividend[i];
      q = Math.floor(x / divisor);
      x -= q * divisor;
      if(quotient.length > 0 || q > 0)
        quotient[quotient.length] = q;
    }
    remainders[j] = x;
    dividend = quotient;
  }

  /* Convert the remainders to the output string */
  var output = "";
  for(i = remainders.length - 1; i >= 0; i--)
    output += encoding.charAt(remainders[i]);

  return output;
}

/*
 * Encode a string as utf-8.
 * For efficiency, this assumes the input is valid utf-16.
 */
function str2rstr_utf8(input)
{
  var output = "";
  var i = -1;
  var x, y;

  while(++i < input.length)
  {
    /* Decode utf-16 surrogate pairs */
    x = input.charCodeAt(i);
    y = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
    if(0xD800 <= x && x <= 0xDBFF && 0xDC00 <= y && y <= 0xDFFF)
    {
      x = 0x10000 + ((x & 0x03FF) << 10) + (y & 0x03FF);
      i++;
    }

    /* Encode output as utf-8 */
    if(x <= 0x7F)
      output += String.fromCharCode(x);
    else if(x <= 0x7FF)
      output += String.fromCharCode(0xC0 | ((x >>> 6 ) & 0x1F),
                                    0x80 | ( x         & 0x3F));
    else if(x <= 0xFFFF)
      output += String.fromCharCode(0xE0 | ((x >>> 12) & 0x0F),
                                    0x80 | ((x >>> 6 ) & 0x3F),
                                    0x80 | ( x         & 0x3F));
    else if(x <= 0x1FFFFF)
      output += String.fromCharCode(0xF0 | ((x >>> 18) & 0x07),
                                    0x80 | ((x >>> 12) & 0x3F),
                                    0x80 | ((x >>> 6 ) & 0x3F),
                                    0x80 | ( x         & 0x3F));
  }
  return output;
}

/*
 * Encode a string as utf-16
 */
function str2rstr_utf16le(input)
{
  var output = "";
  for(var i = 0; i < input.length; i++)
    output += String.fromCharCode( input.charCodeAt(i)        & 0xFF,
                                  (input.charCodeAt(i) >>> 8) & 0xFF);
  return output;
}

function str2rstr_utf16be(input)
{
  var output = "";
  for(var i = 0; i < input.length; i++)
    output += String.fromCharCode((input.charCodeAt(i) >>> 8) & 0xFF,
                                   input.charCodeAt(i)        & 0xFF);
  return output;
}

/*
 * Convert a raw string to an array of little-endian words
 * Characters >255 have their high-byte silently ignored.
 */
function rstr2binl(input)
{
  var output = Array(input.length >> 2);
  for(var i = 0; i < output.length; i++)
    output[i] = 0;
  for(var i = 0; i < input.length * 8; i += 8)
    output[i>>5] |= (input.charCodeAt(i / 8) & 0xFF) << (i%32);
  return output;
}

/*
 * Convert an array of little-endian words to a string
 */
function binl2rstr(input)
{
  var output = "";
  for(var i = 0; i < input.length * 32; i += 8)
    output += String.fromCharCode((input[i>>5] >>> (i % 32)) & 0xFF);
  return output;
}

/*
 * Calculate the MD5 of an array of little-endian words, and a bit length.
 */
function binl_md5(x, len)
{
  /* append padding */
  x[len >> 5] |= 0x80 << ((len) % 32);
  x[(((len + 64) >>> 9) << 4) + 14] = len;

  var a =  1732584193;
  var b = -271733879;
  var c = -1732584194;
  var d =  271733878;

  for(var i = 0; i < x.length; i += 16)
  {
    var olda = a;
    var oldb = b;
    var oldc = c;
    var oldd = d;

    a = md5_ff(a, b, c, d, x[i+ 0], 7 , -680876936);
    d = md5_ff(d, a, b, c, x[i+ 1], 12, -389564586);
    c = md5_ff(c, d, a, b, x[i+ 2], 17,  606105819);
    b = md5_ff(b, c, d, a, x[i+ 3], 22, -1044525330);
    a = md5_ff(a, b, c, d, x[i+ 4], 7 , -176418897);
    d = md5_ff(d, a, b, c, x[i+ 5], 12,  1200080426);
    c = md5_ff(c, d, a, b, x[i+ 6], 17, -1473231341);
    b = md5_ff(b, c, d, a, x[i+ 7], 22, -45705983);
    a = md5_ff(a, b, c, d, x[i+ 8], 7 ,  1770035416);
    d = md5_ff(d, a, b, c, x[i+ 9], 12, -1958414417);
    c = md5_ff(c, d, a, b, x[i+10], 17, -42063);
    b = md5_ff(b, c, d, a, x[i+11], 22, -1990404162);
    a = md5_ff(a, b, c, d, x[i+12], 7 ,  1804603682);
    d = md5_ff(d, a, b, c, x[i+13], 12, -40341101);
    c = md5_ff(c, d, a, b, x[i+14], 17, -1502002290);
    b = md5_ff(b, c, d, a, x[i+15], 22,  1236535329);

    a = md5_gg(a, b, c, d, x[i+ 1], 5 , -165796510);
    d = md5_gg(d, a, b, c, x[i+ 6], 9 , -1069501632);
    c = md5_gg(c, d, a, b, x[i+11], 14,  643717713);
    b = md5_gg(b, c, d, a, x[i+ 0], 20, -373897302);
    a = md5_gg(a, b, c, d, x[i+ 5], 5 , -701558691);
    d = md5_gg(d, a, b, c, x[i+10], 9 ,  38016083);
    c = md5_gg(c, d, a, b, x[i+15], 14, -660478335);
    b = md5_gg(b, c, d, a, x[i+ 4], 20, -405537848);
    a = md5_gg(a, b, c, d, x[i+ 9], 5 ,  568446438);
    d = md5_gg(d, a, b, c, x[i+14], 9 , -1019803690);
    c = md5_gg(c, d, a, b, x[i+ 3], 14, -187363961);
    b = md5_gg(b, c, d, a, x[i+ 8], 20,  1163531501);
    a = md5_gg(a, b, c, d, x[i+13], 5 , -1444681467);
    d = md5_gg(d, a, b, c, x[i+ 2], 9 , -51403784);
    c = md5_gg(c, d, a, b, x[i+ 7], 14,  1735328473);
    b = md5_gg(b, c, d, a, x[i+12], 20, -1926607734);

    a = md5_hh(a, b, c, d, x[i+ 5], 4 , -378558);
    d = md5_hh(d, a, b, c, x[i+ 8], 11, -2022574463);
    c = md5_hh(c, d, a, b, x[i+11], 16,  1839030562);
    b = md5_hh(b, c, d, a, x[i+14], 23, -35309556);
    a = md5_hh(a, b, c, d, x[i+ 1], 4 , -1530992060);
    d = md5_hh(d, a, b, c, x[i+ 4], 11,  1272893353);
    c = md5_hh(c, d, a, b, x[i+ 7], 16, -155497632);
    b = md5_hh(b, c, d, a, x[i+10], 23, -1094730640);
    a = md5_hh(a, b, c, d, x[i+13], 4 ,  681279174);
    d = md5_hh(d, a, b, c, x[i+ 0], 11, -358537222);
    c = md5_hh(c, d, a, b, x[i+ 3], 16, -722521979);
    b = md5_hh(b, c, d, a, x[i+ 6], 23,  76029189);
    a = md5_hh(a, b, c, d, x[i+ 9], 4 , -640364487);
    d = md5_hh(d, a, b, c, x[i+12], 11, -421815835);
    c = md5_hh(c, d, a, b, x[i+15], 16,  530742520);
    b = md5_hh(b, c, d, a, x[i+ 2], 23, -995338651);

    a = md5_ii(a, b, c, d, x[i+ 0], 6 , -198630844);
    d = md5_ii(d, a, b, c, x[i+ 7], 10,  1126891415);
    c = md5_ii(c, d, a, b, x[i+14], 15, -1416354905);
    b = md5_ii(b, c, d, a, x[i+ 5], 21, -57434055);
    a = md5_ii(a, b, c, d, x[i+12], 6 ,  1700485571);
    d = md5_ii(d, a, b, c, x[i+ 3], 10, -1894986606);
    c = md5_ii(c, d, a, b, x[i+10], 15, -1051523);
    b = md5_ii(b, c, d, a, x[i+ 1], 21, -2054922799);
    a = md5_ii(a, b, c, d, x[i+ 8], 6 ,  1873313359);
    d = md5_ii(d, a, b, c, x[i+15], 10, -30611744);
    c = md5_ii(c, d, a, b, x[i+ 6], 15, -1560198380);
    b = md5_ii(b, c, d, a, x[i+13], 21,  1309151649);
    a = md5_ii(a, b, c, d, x[i+ 4], 6 , -145523070);
    d = md5_ii(d, a, b, c, x[i+11], 10, -1120210379);
    c = md5_ii(c, d, a, b, x[i+ 2], 15,  718787259);
    b = md5_ii(b, c, d, a, x[i+ 9], 21, -343485551);

    a = safe_add(a, olda);
    b = safe_add(b, oldb);
    c = safe_add(c, oldc);
    d = safe_add(d, oldd);
  }
  return Array(a, b, c, d);
}

/*
 * These functions implement the four basic operations the algorithm uses.
 */
function md5_cmn(q, a, b, x, s, t)
{
  return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s),b);
}
function md5_ff(a, b, c, d, x, s, t)
{
  return md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
}
function md5_gg(a, b, c, d, x, s, t)
{
  return md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
}
function md5_hh(a, b, c, d, x, s, t)
{
  return md5_cmn(b ^ c ^ d, a, b, x, s, t);
}
function md5_ii(a, b, c, d, x, s, t)
{
  return md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
}

function safe_add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

function bit_rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt));
}

var Namespace = {
	// simple namespace support for classes
	create: function(path, container) {
		// create namespace for class
		if (!container) container = window;
		while (path.match(/^(\w+)\.?/)) {
			var key = RegExp.$1;
			path = path.replace(/^(\w+)\.?/, "");
			if (!container[key]) container[key] = {};
			container = container[key];
		}
		return container;
	},
	prep: function(name, container) {
		// prep namespace for new class
		if (!container) container = window;
		if (name.match(/^(.+)\.(\w+)$/)) {
			var path = RegExp.$1;
			name = RegExp.$2;
			container = Namespace.create(path, container);
		}
		return { container: container, name: name };
	}
};

var Class = {
	// simple class factory
	create: function(name, members) {
		// generate new class with optional namespace

*/	if (this.text) this.parse();
}

XML.prototype.preserveAttributes = false;

XML.prototype.patTag = /([^<]*?)<([^>]+)>/g;
XML.prototype.patSpecialTag = /^\s*([\!\?])/;
XML.prototype.patPITag = /^\s*\?/;
XML.prototype.patCommentTag = /^\s*\!--/;
XML.prototype.patDTDTag = /^\s*\!DOCTYPE/;
XML.prototype.patCDATATag = /^\s*\!\s*\[\s*CDATA/;
XML.prototype.patStandardTag = /^\s*(\/?)([\w\-\:\.]+)\s*(.*)$/;
XML.prototype.patSelfClosing = /\/\s*$/;
XML.prototype.patAttrib = new RegExp("([\\w\\-\\:\\.]+)\\s*=\\s*([\\\"\\'])([^\\2]*?)\\2", "g");
XML.prototype.patPINode = /^\s*\?\s*([\w\-\:]+)\s*(.*)$/;
XML.prototype.patEndComment = /--$/;
XML.prototype.patNextClose = /([^>]*?)>/g;
XML.prototype.patExternalDTDNode = new RegExp("^\\s*\\!DOCTYPE\\s+([\\w\\-\\:]+)\\s+(SYSTEM|PUBLIC)\\s+\\\"([^\\\"]+)\\\"");
XML.prototype.patInlineDTDNode = /^\s*\!DOCTYPE\s+([\w\-\:]+)\s+\[/;
XML.prototype.patEndDTD = /\]$/;
XML.prototype.patDTDNode = /^\s*\!DOCTYPE\s+([\w\-\:]+)\s+\[(.*)\]/;
XML.prototype.patEndCDATA = /\]\]$/;
XML.prototype.patCDATANode = /^\s*\!\s*\[\s*CDATA\s*\[(.*)\]\]/;

XML.prototype.attribsKey = '_Attribs';
XML.prototype.dataKey = '_Data';

XML.prototype.parse = function(branch, name) {
	// parse text into XML tree, recurse for nested nodes
	if (!branch) branch = this.tree;
	if (!name) name = null;
	var foundClosing = false;
	var matches = null;
	
	// match each tag, plus preceding text
	while ( matches = this.patTag.exec(this.text) ) {
		var before = matches[1];
		var tag = matches[2];
		
		// text leading up to tag = content of parent node
		if (before.match(/\S/)) {
			if (typeof(branch[this.dataKey]) != 'undefined') branch[this.dataKey] += ' '; else branch[this.dataKey] = '';
			branch[this.dataKey] += trim(decode_entities(before));
		}
		
		// parse based on tag type
		if (tag.match(this.patSpecialTag)) {
			// special tag
			if (tag.match(this.patPITag)) tag = this.parsePINode(tag);
			else if (tag.match(this.patCommentTag)) tag = this.parseCommentNode(tag);
			else if (tag.match(this.patDTDTag)) tag = this.parseDTDNode(tag);
			else if (tag.match(this.patCDATATag)) {
				tag = this.parseCDATANode(tag);
				if (typeof(branch[this.dataKey]) != 'undefined') branch[this.dataKey] += ' '; else branch[this.dataKey] = '';
				branch[this.dataKey] += trim(decode_entities(tag));
			} // cdata
			else {
				this.throwParseError( "Malformed special tag", tag );
				break;
			} // error
			
			if (tag == null) break;
			continue;
		} // special tag
		else {
			// Tag is standard, so parse name and attributes (if any)
			var matches = tag.match(this.patStandardTag);
			if (!matches) {
				this.throwParseError( "Malformed tag", tag );
				break;
			}
			
			var closing = matches[1];
			var nodeName = matches[2];
			var attribsRaw = matches[3];
			
			// If this is a closing tag, make sure it matches its opening tag
			if (closing) {
				if (nodeName == (name || '')) {
					foundClosing = 1;
					break;
				}
				else {
					this.throwParseError( "Mismatched closing tag (expected </" + name + ">)", tag );
					break;
				}
			} // closing tag
			else {
				// Not a closing tag, so parse attributes into hash.  If tag
				// is self-closing, no recursive parsing is needed.
				var selfClosing = !!attribsRaw.match(this.patSelfClosing);
				var leaf = {};
				var attribs = leaf;
				
				// preserve attributes means they go into a sub-hash named "_Attribs"
				// the XML composer honors this for restoring the tree back into XML
				if (this.preserveAttributes) {
					leaf[this.attribsKey] = {};
					attribs = leaf[this.attribsKey];
				}
				
				// parse attributes
				this.patAttrib.lastIndex = 0;
				while ( matches = this.patAttrib.exec(attribsRaw) ) {
					attribs[ matches[1] ] = decode_entities( matches[3] );
				} // foreach attrib
				
				// if no attribs found, but we created the _Attribs subhash, clean it up now
				if (this.preserveAttributes && !num_keys(attribs)) {
					delete leaf[this.attribsKey];
				}
				
				// Recurse for nested nodes
				if (!selfClosing) {
					this.parse( leaf, nodeName );
					if (this.error()) break;
				}
				
				// Compress into simple node if text only
				var num_leaf_keys = num_keys(leaf);
				if ((typeof(leaf[this.dataKey]) != 'undefined') && (num_leaf_keys == 1)) {
					leaf = leaf[this.dataKey];
				}
				else if (!num_leaf_keys) {
					leaf = '';
				}
				
				// Add leaf to parent branch
				if (typeof(branch[nodeName]) != 'undefined') {
					if (isa_array(branch[nodeName])) {
						array_push( branch[nodeName], leaf );
					}
					else {
						var temp = branch[nodeName];
						branch[nodeName] = [ temp, leaf ];
					}
				}
				else {
					branch[nodeName] = leaf;
				}
				
				if (this.error() || (branch == this.tree)) break;
			} // not closing
		} // standard tag
	} // main reg exp
	
	// Make sure we found the closing tag
	if (name && !foundClosing) {
		this.throwParseError( "Missing closing tag (expected </" + name + ">)", name );
	}
	
	// If we are the master node, finish parsing and setup our doc node
	if (branch == this.tree) {
		if (typeof(this.tree[this.dataKey]) != 'undefined') delete this.tree[this.dataKey];
		
		if (num_keys(this.tree) > 1) {
			this.throwParseError( 'Only one top-level node is allowed in document', first_key(this.tree) );
			return;
		}

		this.documentNodeName = first_key(this.tree);
		if (this.documentNodeName) {
			this.tree = this.tree[this.documentNodeName];
		}
	}
};

XML.prototype.throwParseError = function(key, tag) {
	// log error and locate current line number in source XML document
	var parsedSource = this.text.substring(0, this.patTag.lastIndex);
	var eolMatch = parsedSource.match(/\n/g);
	var lineNum = (eolMatch ? eolMatch.length : 0) + 1;
	lineNum -= tag.match(/\n/) ? tag.match(/\n/g).length : 0;
	
	array_push(this.errors, {
		type: 'Parse',
		key: key,
		text: '<' + tag + '>',
		line: lineNum
	});
};

XML.prototype.error = function() {
	// return number of errors
	return this.errors.length;
};

XML.prototype.getError = function(error) {
	// get formatted error
	var text = '';
	if (!error) return '';

	text = (error.type || 'General') + ' Error';
	if (error.code) text += ' ' + error.code;
	text += ': ' + error.key;
	
	if (error.line) text += ' on line ' + error.line;
	if (error.text) text += ': ' + error.text;

	return text;
};

XML.prototype.getLastError = function() {
	// Get most recently thrown error in plain text format
	if (!this.error()) return '';
	return this.getError( this.errors[this.errors.length - 1] );
};

XML.prototype.parsePINode = function(tag) {
	// Parse Processor Instruction Node, e.g. <?xml version="1.0"?>
	if (!tag.match(this.patPINode)) {
		this.throwParseError( "Malformed processor instruction", tag );
		return null;
	}
	
	array_push( this.piNodeList, tag );
	return tag;
};

XML.prototype.parseCommentNode = function(tag) {
	// Parse Comment Node, e.g. <!-- hello -->
	var matches = null;
	this.patNextClose.lastIndex = this.patTag.lastIndex;
	
	while (!tag.match(this.patEndComment)) {
		if (matches = this.patNextClose.exec(this.text)) {
			tag += '>' + matches[1];
		}
		else {
			this.throwParseError( "Unclosed comment tag", tag );
			return null;
		}
	}
	
	this.patTag.lastIndex = this.patNextClose.lastIndex;
	return tag;
};

XML.prototype.parseDTDNode = function(tag) {
	// Parse Document Type Descriptor Node, e.g. <!DOCTYPE ... >
	var matches = null;
	
	if (tag.match(this.patExternalDTDNode)) {
		// tag is external, and thus self-closing
		array_push( this.dtdNodeList, tag );
	}
	else if (tag.match(this.patInlineDTDNode)) {
		// Tag is inline, so check for nested nodes.
		this.patNextClose.lastIndex = this.patTag.lastIndex;
		
		while (!tag.match(this.patEndDTD)) {
			if (matches = this.patNextClose.exec(this.text)) {
				tag += '>' + matches[1];
			}
			else {
				this.throwParseError( "Unclosed DTD tag", tag );
				return null;
			}
		}
		
		this.patTag.lastIndex = this.patNextClose.lastIndex;
		
		// Make sure complete tag is well-formed, and push onto DTD stack.
		if (tag.match(this.patDTDNode)) {
			array_push( this.dtdNodeList, tag );
		}
		else {
			this.throwParseError( "Malformed DTD tag", tag );
			return null;
		}
	}
	else {
		this.throwParseError( "Malformed DTD tag", tag );
		return null;
	}
	
	return tag;
};

XML.prototype.parseCDATANode = function(tag) {
	// Parse CDATA Node, e.g. <![CDATA[Brooks & Shields]]>
	var matches = null;
	this.patNextClose.lastIndex = this.patTag.lastIndex;
	
	while (!tag.match(this.patEndCDATA)) {
		if (matches = this.patNextClose.exec(this.text)) {
			tag += '>' + matches[1];
		}
		else {
			this.throwParseError( "Unclosed CDATA tag", tag );
			return null;
		}
	}
	
	this.patTag.lastIndex = this.patNextClose.lastIndex;
	
	if (matches = tag.match(this.patCDATANode)) {
		return matches[1];
	}
	else {
		this.throwParseError( "Malformed CDATA tag", tag );
		return null;
	}
};

XML.prototype.getTree = function() {
	// get reference to parsed XML tree
	return this.tree;
};

XML.prototype.compose = function() {
	// compose tree back into XML
	var raw = compose_xml( this.documentNodeName, this.tree );
	var body = raw.substring( raw.indexOf("\n") + 1, raw.length );
	var xml = '';
	
	if (this.piNodeList.length) {
		for (var idx = 0, len = this.piNodeList.length; idx < len; idx++) {
			xml += '<' + this.piNodeList[idx] + '>' + "\n";
		}
	}
	else {
		xml += xml_header + "\n";
	}
	
	if (this.dtdNodeList.length) {
		for (var idx = 0, len = this.dtdNodeList.length; idx < len; idx++) {
			xml += '<' + this.dtdNodeList[idx] + '>' + "\n";
		}
	}
	
	xml += body;
	return xml;
};

//
// Static Utility Functions:
//

function parse_xml(text) {
	// turn text into XML tree quickly
	var parser = new XML(text);
	return parser.error() ? parser.getLastError() : parser.getTree();
}

function trim(text) {
	// strip whitespace from beginning and end of string
	if (text == null) return '';
	
	if (text && text.replace) {
		text = text.replace(/^\s+/, "");
		text = text.replace(/\s+$/, "");
	}
	
	return text;
}

function encode_entities(text) {
	// Simple entitize function for composing XML
	if (text == null) return '';

	if (text && text.replace) {
		text = text.replace(/\&/g, "&amp;"); // MUST BE FIRST
		text = text.replace(/</g, "&lt;");
		text = text.replace(/>/g, "&gt;");
	}

	return text;
}

function encode_attrib_entities(text) {
	// Simple entitize function for composing XML attributes
	if (text == null) return '';

	if (text && text.replace) {
		text = text.replace(/\&/g, "&amp;"); // MUST BE FIRST
		text = text.replace(/</g, "&lt;");
		text = text.replace(/>/g, "&gt;");
		text = text.replace(/\"/g, "&quot;");
		text = text.replace(/\'/g, "&apos;");
	}

	return text;
}

function decode_entities(text) {
	// Decode XML entities into raw ASCII
	if (text == null) return '';

	if (text && text.replace) {
		text = text.replace(/\&lt\;/g, "<");
		text = text.replace(/\&gt\;/g, ">");
		text = text.replace(/\&quot\;/g, '"');
		text = text.replace(/\&apos\;/g, "'");
		text = text.replace(/\&amp\;/g, "&"); // MUST BE LAST
	}

	return text;
}

function compose_xml(name, node, indent) {
	// Compose node into XML including attributes
	// Recurse for child nodes
	var xml = "";
	
	// If this is the root node, set the indent to 0
	// and setup the XML header (PI node)
	if (!indent) {
		indent = 0;
		xml = xml_header + "\n";
	}
	
	// Setup the indent text
	var indent_text = "";
	for (var k = 0; k < indent; k++) indent_text += indent_string;

	if ((typeof(node) == 'object') && (node != null)) {
		// node is object -- now see if it is an array or hash
		if (!node.length) { // what about zero-length array?
			// node is hash
			xml += indent_text + "<" + name;

			var num_keys = 0;
			var has_attribs = 0;
			for (var key in node) num_keys++; // there must be a better way...

			if (node["_Attribs"]) {
				has_attribs = 1;
				var sorted_keys = hash_keys_to_array(node["_Attribs"]).sort();
				for (var idx = 0, len = sorted_keys.length; idx < len; idx++) {
					var key = sorted_keys[idx];
					xml += " " + key + "=\"" + encode_attrib_entities(node["_Attribs"][key]) + "\"";
				}
			} // has attribs

			if (num_keys > has_attribs) {
				// has child elements
				xml += ">";

				if (node["_Data"]) {
					// simple text child node
					xml += encode_entities(node["_Data"]) + "</" + name + ">\n";
				} // just text
				else {
					xml += "\n";
					
					var sorted_keys = hash_keys_to_array(node).sort();
					for (var idx = 0, len = sorted_keys.length; idx < len; idx++) {
						var key = sorted_keys[idx];					
						if ((key != "_Attribs") && key.match(re_valid_tag_name)) {
							// recurse for node, with incremented indent value
							xml += compose_xml( key, node[key], indent + 1 );
						} // not _Attribs key
					} // foreach key

					xml += indent_text + "</" + name + ">\n";
				} // real children
			}
			else {
				// no child elements, so self-close
				xml += "/>\n";
			}
		} // standard node
		else {
			// node is array
			for (var idx = 0; idx < node.length; idx++) {
				// recurse for node in array with same indent
				xml += compose_xml( name, node[idx], indent );
			}
		} // array of nodes
	} // complex node
	else {
		// node is simple string
		xml += indent_text + "<" + name + ">" + encode_entities(node) + "</" + name + ">\n";
	} // simple text node

	return xml;
}

function find_object(obj, criteria) {
	// walk array looking for nested object matching criteria object
	if (isa_hash(obj)) obj = hash_values_to_array(obj);
	
	var criteria_length = 0;
	for (var a in criteria) criteria_length++;
	obj = always_array(obj);
	
	for (var a = 0; a < obj.length; a++) {
		var matches = 0;
		
		for (var b in criteria) {
			if (obj[a][b] && (obj[a][b] == criteria[b])) matches++;
			else if (obj[a]["_Attribs"] && obj[a]["_Attribs"][b] && (obj[a]["_Attribs"][b] == criteria[b])) matches++;
		}
		if (matches >= criteria_length) return obj[a];
	}
	return null;
}

function find_objects(obj, criteria) {
	// walk array gathering all nested objects that match criteria object
	if (isa_hash(obj)) obj = hash_values_to_array(obj);
	
	var objs = new Array();
	var criteria_length = 0;
	for (var a in criteria) criteria_length++;
	obj = always_array(obj);
	
	for (var a = 0; a < obj.length; a++) {
		var matches = 0;
		for (var b in criteria) {
			if (obj[a][b] && obj[a][b] == criteria[b]) matches++;
			else if (obj[a]["_Attribs"] && obj[a]["_Attribs"][b] && (obj[a]["_Attribs"][b] == criteria[b])) matches++;
		}
		if (matches >= criteria_length) array_push( objs, obj[a] );
	}
	
	return objs;
}

function find_object_idx(obj, criteria) {
	// walk array looking for nested object matching criteria object
	// return index in outer array, not object itself
	if (isa_hash(obj)) obj = hash_values_to_array(obj);
	
	var criteria_length = 0;
	for (var a in criteria) criteria_length++;
	obj = always_array(obj);
	
	for (var idx = 0; idx < obj.length; idx++) {
		var matches = 0;
		
		for (var b in criteria) {
			if (obj[idx][b] && (obj[idx][b] == criteria[b])) matches++;
			else if (obj[idx]["_Attribs"] && obj[idx]["_Attribs"][b] && (obj[idx]["_Attribs"][b] == criteria[b])) matches++;
		}
		if (matches >= criteria_length) return idx;
	}
	return -1;
}

function delete_object(obj, criteria) {
	// walk array looking for nested object matching criteria object
	// delete first object found
	var idx = find_object_idx(obj, criteria);

	if (idx > -1) {
		obj.splice( idx, 1 );
		return true;
	}
	return false;
}

function delete_objects(obj, criteria) {
	// delete all objects in obj array matching criteria
	while (delete_object(obj, criteria)) ;
}

function always_array(obj, key) {
	// if object is not array, return array containing object
	// if key is passed, work like XMLalwaysarray() instead
	// apparently MSIE has weird issues with obj = always_array(obj);
	
	if (key) {
		if ((typeof(obj[key]) != 'object') || (typeof(obj[key].length) == 'undefined')) {
			var temp = obj[key];
			delete obj[key];
			obj[key] = new Array();
			obj[key][0] = temp;
		}
		return null;
	}
	else {
		if ((typeof(obj) != 'object') || (typeof(obj.length) == 'undefined')) { return [ obj ]; }
		else return obj;
	}
}

function hash_keys_to_array(hash) {
	// convert hash keys to array (discard values)
	var array = [];
	for (var key in hash) array_push(array, key);
	return array;
}

function hash_values_to_array(hash) {
	// convert hash values to array (discard keys)
	var arr = [];
	for (var key in hash) arr.push( hash[key] );
	return arr;
};

function merge_objects(a, b) {
	// merge keys from a and b into c and return c
	// b has precedence over a
	if (!a) a = {};
	if (!b) b = {};
	var c = {};

	// also handle serialized objects for a and b
	if (typeof(a) != 'object') eval( "a = " + a );
	if (typeof(b) != 'object') eval( "b = " + b );

	for (var key in a) c[key] = a[key];
	for (var key in b) c[key] = b[key];

	return c;
}

function copy_object(obj) {
	// return copy of object (NOT DEEP)
	var new_obj = {};
	for (var key in obj) new_obj[key] = obj[key];
	return new_obj;
}

function deep_copy_object(obj) {
	// recursively copy object and nested objects
	// return new object
	return JSON.parse( JSON.stringify(obj) );
}

function copy_into_object(a, b) {
	// copy b in to a (NOT DEEP)
	// no return value
	for (var key in b) a[key] = b[key];
}

function num_keys(hash) {
	// count the number of keys in a hash
	var count = 0;
	for (var a in hash) count++;
	return count;
}

function reverse_hash(a) {
	// reverse hash keys/values
	var c = {};
	for (var key in a) {
		c[ a[key] ] = key;
	}
	return c;
}

function lookup_path(path, obj) {
	// walk through object tree, psuedo-XPath-style
	// supports arrays as well as objects
	// return final object or value
	// always start query with a slash, i.e. /something/or/other
	path = path.replace(/\/$/, ""); // strip trailing slash
	
	while (/\/[^\/]+/.test(path) && (typeof(obj) == 'object')) {
		// find first slash and strip everything up to and including it
		var slash = path.indexOf('/');
		path = path.substring( slash + 1 );
		
		// find next slash (or end of string) and get branch name
		slash = path.indexOf('/');
		if (slash == -1) slash = path.length;
		var name = path.substring(0, slash);

		// advance obj using branch
		if (typeof(obj.length) == 'undefined') {
			// obj is hash
			if (typeof(obj[name]) != 'undefined') obj = obj[name];
			else return null;
		}
		else {
			// obj is array
			var idx = parseInt(name, 10);
			if (isNaN(idx)) return null;
			if (typeof(obj[idx]) != 'undefined') obj = obj[idx];
			else return null;
		}

	} // while path contains branch

	return obj;
}

function isa_hash(arg) {
	// determine if arg is a hash
	return( !!arg && (typeof(arg) == 'object') && (typeof(arg.length) == 'undefined') );
}

function isa_array(arg) {
	// determine if arg is an array or is array-like
	if (typeof(arg) == 'array') return true;
	return( !!arg && (typeof(arg) == 'object') && (typeof(arg.length) != 'undefined') );
}

function first_key(hash) {
	// return first key from hash (unordered)
	for (var key in hash) return key;
	return null; // no keys in hash
}

function array_push(array, item) {
	// push item onto end of array
	array[ array.length ] = item;
}

function rand_array(arr) {
	// return random element from array
	return arr[ parseInt(Math.random() * arr.length, 10) ];
}

function find_in_array(arr, elem) {
	// return true if elem is found in arr, false otherwise
	for (var idx = 0, len = arr.length; idx < len; idx++) {
		if (arr[idx] == elem) return true;
	}
	return false;
}

var months = [
	[ 1, 'January' ], [ 2, 'February' ], [ 3, 'March' ], [ 4, 'April' ],
	[ 5, 'May' ], [ 6, 'June' ], [ 7, 'July' ], [ 8, 'August' ],
	[ 9, 'September' ], [ 10, 'October' ], [ 11, 'November' ],
	[ 12, 'December' ]
];

function parse_query_string(url) {
	// parse query string into key/value pairs and return as object
	var query = {}; 
	url.replace(/^.*\?/, '').replace(/([^\=]+)\=([^\&]*)\&?/g, function(match, key, value) {
		query[key] = decodeURIComponent(value);
		if (query[key].match(/^\-?\d+$/)) query[key] = parseInt(query[key]);
		else if (query[key].match(/^\-?\d*\.\d+$/)) query[key] = parseFloat(query[key]);
		return ''; 
	} );
	return query; 
};

function compose_query_string(queryObj) {
	// compose key/value pairs into query string
	// supports duplicate keys (i.e. arrays)
	var qs = '';
	for (var key in queryObj) {
		var values = always_array(queryObj[key]);
		for (var idx = 0, len = values.length; idx < len; idx++) {
			qs += (qs.length ? '&' : '?') + escape(key) + '=' + escape(values[idx]);
		}
	}
	return qs;
}

function get_text_from_bytes(bytes, precision) {
	// convert raw bytes to english-readable format
	// set precision to 1 for ints, 10 for 1 decimal point (default), 100 for 2, etc.
	bytes = Math.floor(bytes);
	if (!precision) precision = 10;
	
	if (bytes >= 1024) {
		bytes = Math.floor( (bytes / 1024) * precision ) / precision;
		if (bytes >= 1024) {
			bytes = Math.floor( (bytes / 1024) * precision ) / precision;
			if (bytes >= 1024) {
				bytes = Math.floor( (bytes / 1024) * precision ) / precision;
				if (bytes >= 1024) {
					bytes = Math.floor( (bytes / 1024) * precision ) / precision;
					return bytes + ' TB';
				} 
				else return bytes + ' GB';
			} 
			else return bytes + ' MB';
		}
		else return bytes + ' K';
	}
	else return bytes + pluralize(' byte', bytes);
};

function get_bytes_from_text(text) {
	// parse text into raw bytes, e.g. "1 K" --> 1024
	if (text.toString().match(/^\d+$/)) return parseInt(text); // already in bytes
	var multipliers = {
		b: 1,
		k: 1024,
		m: 1024 * 1024,
		g: 1024 * 1024 * 1024,
		t: 1024 * 1024 * 1024 * 1024
	};
	var bytes = 0;
	text = text.toString().replace(/([\d\.]+)\s*(\w)\w*\s*/g, function(m_all, m_g1, m_g2) {
		var mult = multipliers[ m_g2.toLowerCase() ] || 0;
		bytes += (parseFloat(m_g1) * mult); 
		return '';
	} );
	return Math.floor(bytes);
};

function ucfirst(text) {
	// capitalize first character only, lower-case rest
	return text.substring(0, 1).toUpperCase() + text.substring(1, text.length).toLowerCase();
}

function commify(number) {
	// add commas to integer, like 1,234,567
	if (!number) number = 0;

	number = '' + number;
	if (number.length > 3) {
		var mod = number.length % 3;
		var output = (mod > 0 ? (number.substring(0,mod)) : '');
		for (i=0 ; i < Math.floor(number.length / 3); i++) {
			if ((mod == 0) && (i == 0))
				output += number.substring(mod+ 3 * i, mod + 3 * i + 3);
			else
				output+= ',' + number.substring(mod + 3 * i, mod + 3 * i + 3);
		}
		return (output);
	}
	else return number;
}

function short_float(value, places) {
	// Shorten floating-point decimal to N places max
	if (!places) places = 2;
	var mult = Math.pow(10, places);
	return( Math.floor(parseFloat(value || 0) * mult) / mult );
}

function pct(count, max, floor) {
	// Return formatted percentage given a number along a sliding scale from 0 to 'max'
	var pct = (count * 100) / (max || 1);
	if (!pct.toString().match(/^\d+(\.\d+)?$/)) { pct = 0; }
	return '' + (floor ? Math.floor(pct) : short_float(pct)) + '%';
};

function get_text_from_seconds(sec, abbrev, no_secondary) {
	// convert raw seconds to human-readable relative time
	var neg = '';
	sec = parseInt(sec, 10);
	if (sec<0) { sec =- sec; neg = '-'; }
	
	var p_text = abbrev ? "sec" : "second";
	var p_amt = sec;
	var s_text = "";
	var s_amt = 0;
	
	if (sec > 59) {
		var min = parseInt(sec / 60, 10);
		sec = sec % 60; 
		s_text = abbrev ? "sec" : "second"; 
		s_amt = sec; 
		p_text = abbrev ? "min" : "minute"; 
		p_amt = min;
		
		if (min > 59) {
			var hour = parseInt(min / 60, 10);
			min = min % 60; 
			s_text = abbrev ? "min" : "minute"; 
			s_amt = min; 
			p_text = abbrev ? "hr" : "hour"; 
			p_amt = hour;
			
			if (hour > 23) {
				var day = parseInt(hour / 24, 10);
				hour = hour % 24; 
				s_text = abbrev ? "hr" : "hour"; 
				s_amt = hour; 
				p_text = "day"; 
				p_amt = day;
				
				if (day > 29) {
					var month = parseInt(day / 30, 10);
					s_text = "day"; 
					s_amt = day % 30; 
					p_text = abbrev ? "mon" : "month"; 
					p_amt = month;
					
					if (day >= 365) {
						var year = parseInt(day / 365, 10);
						month = month % 12; 
						s_text = abbrev ? "mon" : "month"; 
						s_amt = month; 
						p_text = abbrev ? "yr" : "year"; 
						p_amt = year;
					} // day>=365
				} // day>29
			} // hour>23
		} // min>59
	} // sec>59
	
	var text = p_amt + "&nbsp;" + p_text;
	if ((p_amt != 1) && !abbrev) text += "s";
	if (s_amt && !no_secondary) {
		text += ", " + s_amt + "&nbsp;" + s_text;
		if ((s_amt != 1) && !abbrev) text += "s";
	}
	
	return(neg + text);
}

function get_text_from_seconds_round(sec, abbrev) {
	// convert raw seconds to human-readable relative time
	// round to nearest instead of floor
	var neg = '';
	sec = Math.round(sec);
	if (sec < 0) { sec =- sec; neg = '-'; }
	
	var text = abbrev ? "sec" : "second";
	var amt = sec;
	
	if (sec > 59) {
		var min = Math.round(sec / 60);
		text = abbrev ? "min" : "minute"; 
		amt = min;
		
		if (min > 59) {
			var hour = Math.round(min / 60);
			text = abbrev ? "hr" : "hour"; 
			amt = hour;
			
			if (hour > 23) {
				var day = Math.round(hour / 24);
				text = "day"; 
				amt = day;
			} // hour>23
		} // min>59
	} // sec>59
	
	var text = "" + amt + " " + text;
	if ((amt != 1) && !abbrev) text += "s";
	
	return(neg + text);
};

function get_seconds_from_text(text) {
	// parse text into raw seconds, e.g. "1 minute" --> 60
	if (text.toString().match(/^\d+$/)) return parseInt(text); // already in seconds
	var multipliers = {
		s: 1,
		m: 60,
		h: 60 * 60,
		d: 60 * 60 * 24,
		w: 60 * 60 * 24 * 7
	};
	var seconds = 0;
	text = text.toString().replace(/([\d\.]+)\s*(\w)\w*\s*/g, function(m_all, m_g1, m_g2) {
		var mult = multipliers[ m_g2.toLowerCase() ] || 0;
		seconds += (parseFloat(m_g1) * mult); 
		return '';
	} );
	return Math.floor(seconds);
};

function get_inner_window_size(dom) {
	// get size of inner window
	if (!dom) dom = window;
	var myWidth = 0, myHeight = 0;
	
	if( typeof( dom.innerWidth ) == 'number' ) {
		// Non-IE
		myWidth = dom.innerWidth;
		myHeight = dom.innerHeight;
	}
	else if( dom.document.documentElement && ( dom.document.documentElement.clientWidth || dom.document.documentElement.clientHeight ) ) {
		// IE 6+ in 'standards compliant mode'
		myWidth = dom.document.documentElement.clientWidth;
		myHeight = dom.document.documentElement.clientHeight;
	}
	else if( dom.document.body && ( dom.document.body.clientWidth || dom.document.body.clientHeight ) ) {
		// IE 4 compatible
		myWidth = dom.document.body.clientWidth;
		myHeight = dom.document.body.clientHeight;
	}
	return { width: myWidth, height: myHeight };
}

function get_scroll_xy(dom) {
	// get page scroll X, Y
	if (!dom) dom = window;
  var scrOfX = 0, scrOfY = 0;
  if( typeof( dom.pageYOffset ) == 'number' ) {
    //Netscape compliant
    scrOfY = dom.pageYOffset;
    scrOfX = dom.pageXOffset;
  } else if( dom.document.body && ( dom.document.body.scrollLeft || dom.document.body.scrollTop ) ) {
    //DOM compliant
    scrOfY = dom.document.body.scrollTop;
    scrOfX = dom.document.body.scrollLeft;
  } else if( dom.document.documentElement && ( dom.document.documentElement.scrollLeft || dom.document.documentElement.scrollTop ) ) {
    //IE6 standards compliant mode
    scrOfY = dom.document.documentElement.scrollTop;
    scrOfX = dom.document.documentElement.scrollLeft;
  }
  return { x: scrOfX, y: scrOfY };
}

function get_scroll_max(dom) {
	// get maximum scroll width/height
	if (!dom) dom = window;
	var myWidth = 0, myHeight = 0;
	if (dom.document.body.scrollHeight) {
		myWidth = dom.document.body.scrollWidth;
		myHeight = dom.document.body.scrollHeight;
	}
	else if (dom.document.documentElement.scrollHeight) {
		myWidth = dom.document.documentElement.scrollWidth;
		myHeight = dom.document.documentElement.scrollHeight;
	}
	return { width: myWidth, height: myHeight };
}

function hires_time_now() {
	// return the Epoch seconds for like right now
	var now = new Date();
	return ( now.getTime() / 1000 );
}

function str_value(str) {
	// Get friendly string value for display purposes.
	if (typeof(str) == 'undefined') str = '';
	else if (str === null) str = '';
	return '' + str;
}

function pluralize(word, num) {
	// Pluralize a word using simplified English language rules.
	if (num != 1) {
		if (word.match(/[^e]y$/)) return word.replace(/y$/, '') + 'ies';
		else if (word.match(/s$/)) return word + 'es'; // processes
		else return word + 's';
	}
	else return word;
}

function render_menu_options(items, sel_value, auto_add) {
	// return HTML for menu options
	var html = '';
	var found = false;
	
	for (var idx = 0, len = items.length; idx < len; idx++) {
		var item = items[idx];
		var item_name = '';
		var item_value = '';
		if (isa_hash(item)) {
			if (('label' in item) && ('data' in item)) {
				item_name = item.label;
				item_value = item.data;
			}
			else {
				item_name = item.title;
				item_value = item.id;
			}
		}
		else if (isa_array(item)) {
			item_value = item[0];
			item_name = item[1];
		}
		else {
			item_name = item_value = item;
		}
		html += '<option value="'+item_value+'" '+((item_value == sel_value) ? 'selected="selected"' : '')+'>'+item_name+'</option>';
		if (item_value == sel_value) found = true;
	}
	
	if (!found && (str_value(sel_value) != '') && auto_add) {
		html += '<option value="'+sel_value+'" selected="selected">'+sel_value+'</option>';
	}
	
	return html;
}

function dirname(path) {
	// return path excluding file at end (same as POSIX function of same name)
	return path.toString().replace(/\/$/, "").replace(/\/[^\/]+$/, "");
}

function basename(path) {
	// return filename, strip path (same as POSIX function of same name)
	return path.toString().replace(/\/$/, "").replace(/^(.*)\/([^\/]+)$/, "$2");
}

function strip_ext(path) {
	// strip extension from filename
	return path.toString().replace(/\.\w+$/, "");
}

function load_script(url) {
	// Dynamically load script into DOM.
	Debug.trace( "Loading script: " + url );
	var scr = document.createElement('SCRIPT');
	scr.type = 'text/javascript';
	scr.src = url;
	document.getElementsByTagName('HEAD')[0].appendChild(scr);
}

function compose_attribs(attribs) {
	// compose Key="Value" style attributes for HTML elements
	var html = '';
	
	if (attribs) {
		for (var key in attribs) {
			html += " " + key + "=\"" + attribs[key] + "\"";
		}
	}

	return html;
}

function compose_style(attribs) {
	// compose key:value; pairs for style (CSS) elements
	var html = '';
	
	if (attribs) {
		for (var key in attribs) {
			html += " " + key + ":" + attribs[key] + ";";
		}
	}

	return html;
}

function truncate_ellipsis(str, len) {
	// simple truncate string with ellipsis if too long
	str = str_value(str);
	if (str.length > len) {
		str = str.substring(0, len - 3) + '...';
	}
	return str;
}

function escape_text_field_value(text) {
	// escape text field value, with stupid IE support
	text = encode_attrib_entities( str_value(text) );
	if (navigator.userAgent.match(/MSIE/) && text.replace) text = text.replace(/\&apos\;/g, "'");
	return text;
}

function expando_text(text, max, link) {
	// if text is longer than max chars, chop with ellipsis and include link to show all
	if (!link) link = 'More';
	text = str_value(text);
	if (text.length <= max) return text;
	
	var before = text.substring(0, max);
	var after = text.substring(max);
	
	return before + 
		'<span>... <a href="javascript:void(0)" onMouseUp="$(this).parent().hide().next().show()">'+link+'</a></span>' + 
		'<span style="display:none">' + after + '</span>';
};

function get_int_version(str, pad) {
	// Joe's Fun Multi-Decimal Comparision Trick
	// Example: convert 2.5.1 to 2005001 for numerical comparison against other similar "numbers".
	if (!pad) pad = 3;
	str = str_value(str).replace(/[^\d\.]+/g, '');
	if (!str.match(/\./)) return parseInt(str, 10);
	
	var parts = str.split(/\./);
	var output = '';
	for (var idx = 0, len = parts.length; idx < len; idx++) {
		var part = '' + parts[idx];
		while (part.length < pad) part = '0' + part;
		output += part;
	}
	return parseInt( output.replace(/^0+/, ''), 10 );
};

function get_unique_id(len, salt) {
	// Get unique ID using MD5, hires time, pseudo-random number and static counter.
	if (this.__unique_id_counter) this.__unique_id_counter = 0;
	this.__unique_id_counter++;
	return hex_md5( '' + hires_time_now() + Math.random() + this.__unique_id_counter + (salt || '') ).substring(0, len || 32);
};

function escape_regexp(text) {
	// Escape text for use in a regular expression.
	return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
};

function setPath(target, path, value) {
	// set path using dir/slash/syntax or dot.path.syntax
	// preserve dots and slashes if escaped
	var parts = path.replace(/\\\./g, '__PXDOT__').replace(/\\\//g, '__PXSLASH__').split(/[\.\/]/).map( function(elem) {
		return elem.replace(/__PXDOT__/g, '.').replace(/__PXSLASH__/g, '/');
	} );
	
	var key = parts.pop();
	
	// traverse path
	while (parts.length) {
		var part = parts.shift();
		if (part) {
			if (!(part in target)) {
				// auto-create nodes
				target[part] = {};
			}
			if (typeof(target[part]) != 'object') {
				// path runs into non-object
				return false;
			}
			target = target[part];
		}
	}
	
	target[key] = value;
	return true;
};

function getPath(target, path) {
	// get path using dir/slash/syntax or dot.path.syntax
	// preserve dots and slashes if escaped
	var parts = path.replace(/\\\./g, '__PXDOT__').replace(/\\\//g, '__PXSLASH__').split(/[\.\/]/).map( function(elem) {
		return elem.replace(/__PXDOT__/g, '.').replace(/__PXSLASH__/g, '/');
	} );
	
	var key = parts.pop();
	
	// traverse path
	while (parts.length) {
		var part = parts.shift();
		if (part) {
			if (typeof(target[part]) != 'object') {
				// path runs into non-object
				return undefined;
			}
			target = target[part];
		}
	}
	
	return target[key];
};

function substitute(text, args, fatal) {
	// perform simple [placeholder] substitution using supplied
	// args object and return transformed text
	var self = this;
	var result = true;
	var value = '';
	if (typeof(text) == 'undefined') text = '';
	text = '' + text;
	if (!args) args = {};
	
	text = text.replace(/\[([^\]]+)\]/g, function(m_all, name) {
		value = getPath(args, name);
		if (value === undefined) {
			result = false;
			return m_all;
		}
		else return value;
	} );
	
	if (!result && fatal) return null;
	else return text;
};

var _months = [
	[ 1, 'January' ], [ 2, 'February' ], [ 3, 'March' ], [ 4, 'April' ],
	[ 5, 'May' ], [ 6, 'June' ], [ 7, 'July' ], [ 8, 'August' ],
	[ 9, 'September' ], [ 10, 'October' ], [ 11, 'November' ],
	[ 12, 'December' ]
];
var _days = [
	[1,1], [2,2], [3,3], [4,4], [5,5], [6,6], [7,7], [8,8], [9,9], [10,10],
	[11,11], [12,12], [13,13], [14,14], [15,15], [16,16], [17,17], [18,18], 
	[19,19], [20,20], [21,21], [22,22], [23,23], [24,24], [25,25], [26,26],
	[27,27], [28,28], [29,29], [30,30], [31,31]
];

var _short_month_names = [ 'Jan', 'Feb', 'Mar', 'Apr', 'May', 
	'June', 'July', 'Aug', 'Sept', 'Oct', 'Nov', 'Dec' ];

var _day_names = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 
	'Thursday', 'Friday', 'Saturday'];
	
var _short_day_names = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

var _number_suffixes = ['th', 'st', 'nd', 'rd', 'th', 'th', 'th', 'th', 'th', 'th'];

var _hour_names = ['12am', '1am', '2am', '3am', '4am', '5am', '6am', '7am', '8am', '9am', '10am', '11am', '12pm', '1pm', '2pm', '3pm', '4pm', '5pm', '6pm', '7pm', '8pm', '9pm', '10pm', '11pm'];

function time_now() {
	// return the Epoch seconds for like right now
	var now = new Date();
	return Math.floor( now.getTime() / 1000 );
}

function hires_time_now() {
	// return the Epoch seconds for like right now
	var now = new Date();
	return ( now.getTime() / 1000 );
}

function format_date(thingy, template) {
	// format date using get_date_args
	// e.g. '[yyyy]/[mm]/[dd]' or '[dddd], [mmmm] [mday], [yyyy]' or '[hour12]:[mi] [ampm]'
	if (!thingy) return false;
	var dargs = thingy.yyyy_mm_dd ? thingy : get_date_args(thingy);
	return template.replace(/\[(\w+)\]/g, function(m_all, m_g1) {
		return (m_g1 in dargs) ? dargs[m_g1] : '';
	});
}

function get_date_args(thingy) {
	// return hash containing year, mon, mday, hour, min, sec
	// given epoch seconds
	var date = (typeof(thingy) == 'object') ? thingy : (new Date( (typeof(thingy) == 'number') ? (thingy * 1000) : thingy ));
	var args = {
		epoch: Math.floor( date.getTime() / 1000 ),
		year: date.getFullYear(),
		mon: date.getMonth() + 1,
		mday: date.getDate(),
		hour: date.getHours(),
		min: date.getMinutes(),
		sec: date.getSeconds(),
		msec: date.getMilliseconds(),
		wday: date.getDay(),
		offset: 0 - (date.getTimezoneOffset() / 60)
	};
	
	args.yyyy = '' + args.year;
	if (args.mon < 10) args.mm = "0" + args.mon; else args.mm = '' + args.mon;
	if (args.mday < 10) args.dd = "0" + args.mday; else args.dd = '' + args.mday;
	if (args.hour < 10) args.hh = "0" + args.hour; else args.hh = '' + args.hour;
	if (args.min < 10) args.mi = "0" + args.min; else args.mi = '' + args.min;
	if (args.sec < 10) args.ss = "0" + args.sec; else args.ss = '' + args.sec;
	
	if (args.hour >= 12) {
		args.ampm = 'pm';
		args.hour12 = args.hour - 12;
		if (!args.hour12) args.hour12 = 12;
	}
	else {
		args.ampm = 'am';
		args.hour12 = args.hour;
		if (!args.hour12) args.hour12 = 12;
	}
	
	args.AMPM = args.ampm.toUpperCase();
	args.yyyy_mm_dd = args.yyyy + '/' + args.mm + '/' + args.dd;
	args.hh_mi_ss = args.hh + ':' + args.mi + ':' + args.ss;
	args.tz = 'GMT' + (args.offset > 0 ? '+' : '') + args.offset;
	
	// add formatted month and weekdays
	args.mmm = _short_month_names[ args.mon - 1 ];
	args.mmmm = _months[ args.mon - 1] ? _months[ args.mon - 1][1] : '';
	args.ddd = _short_day_names[ args.wday ];
	args.dddd = _day_names[ args.wday ];
	
	return args;
}

function get_time_from_args(args) {
	// return epoch given args like those returned from get_date_args()
	var then = new Date(
		args.year,
		args.mon - 1,
		args.mday,
		args.hour,
		args.min,
		args.sec,
		0
	);
	return parseInt( then.getTime() / 1000, 10 );
}

function yyyy(epoch) {
	// return current year (or epoch) in YYYY format
	if (!epoch) epoch = time_now();
	var args = get_date_args(epoch);
	return args.year;
}

function yyyy_mm_dd(epoch, ch) {
	// return current date (or custom epoch) in YYYY/MM/DD format
	if (!epoch) epoch = time_now();
	if (!ch) ch = '/';
	var args = get_date_args(epoch);
	return args.yyyy + ch + args.mm + ch + args.dd;
}

function mm_dd_yyyy(epoch, ch) {
	// return current date (or custom epoch) in YYYY/MM/DD format
	if (!epoch) epoch = time_now();
	if (!ch) ch = '/';
	var args = get_date_args(epoch);
	return args.mm + ch + args.dd + ch + args.yyyy;
}

function normalize_time(epoch, zero_args) {
	// quantize time into any given precision
	// example hourly: { min:0, sec:0 }
	// daily: { hour:0, min:0, sec:0 }
	var args = get_date_args(epoch);
	for (key in zero_args) args[key] = zero_args[key];

	// mday is 1-based
	if (!args['mday']) args['mday'] = 1;

	return get_time_from_args(args);
}

function get_nice_date(epoch, abbrev) {
	var dargs = get_date_args(epoch);
	var month = window._months[dargs.mon - 1][1];
	if (abbrev) month = month.substring(0, 3);
	return month + ' ' + dargs.mday + ', ' + dargs.year;
}

function get_nice_time(epoch, secs) {
	// return time in HH12:MM format
	var dargs = get_date_args(epoch);
	if (dargs.min < 10) dargs.min = '0' + dargs.min;
	if (dargs.sec < 10) dargs.sec = '0' + dargs.sec;
	var output = dargs.hour12 + ':' + dargs.min;
	if (secs) output += ':' + dargs.sec;
	output += ' ' + dargs.ampm.toUpperCase();
	return output;
}

function get_nice_date_time(epoch, secs, abbrev_date) {
	return get_nice_date(epoch, abbrev_date) + ' ' + get_nice_time(epoch, secs);
}

function get_short_date_time(epoch) {
	return get_nice_date(epoch, true) + ' ' + get_nice_time(epoch, false);
}

function parse_date(str) {
	// parse date into epoch
	return Math.floor( ((new Date(str)).getTime() / 1000) );
};

function check_valid_date(str) {
	var epoch = 0;
	try { epoch = parse_date(str); }
	catch (e) { epoch = 0; }
	return (epoch >= 86400);
};


var Nav = {
	
	/**
	 * Virtual Page Navigation System
	 **/
	
	loc: '',
	old_loc: '',
	inited: false,
	nodes: [],
	
	init: function() {
		// initialize nav system
		assert( window.config, "window.config not present.");
		
		if (!this.inited) {
			this.inited = true;
			this.loc = 'init';
			this.monitor();
			
			if (window.addEventListener) {
				window.addEventListener("hashchange", function(event) {
					Nav.monitor();
				}, false);
			}
			else {
				window.onhashchange = function() { Nav.monitor(); };
			}
		}
	},
	
	monitor: function() {
		// monitor browser location and activate handlers as needed
		var parts = window.location.href.split(/\#/);
		var anchor = parts[1];
		if (!anchor) anchor = config.DefaultPage || 'Main';
		
		var full_anchor = '' + anchor;
		var sub_anchor = '';
		
		anchor = anchor.replace(/\%7C/, '|');
		if (anchor.match(/\|(\w+)$/)) {
			// inline section anchor after article name, pipe delimited
			sub_anchor = RegExp.$1.toLowerCase();
			anchor = anchor.replace(/\|(\w+)$/, '');
		}
		
		if ((anchor != this.loc) && !anchor.match(/^_/)) { // ignore doxter anchors
			Debug.trace('nav', "Caught navigation anchor: " + full_anchor);
			
			var page_name = '';
			var page_args = {};
			if (full_anchor.match(/^\w+\?.+/)) {
				parts = full_anchor.split(/\?/);
				page_name = parts[0];
				page_args = parse_query_string( parts[1] );
			}
			else {
				parts = full_anchor.split(/\//);
				page_name = parts[0];
				page_args = {};
			}
			
			Debug.trace('nav', "Calling page: " + page_name + ": " + JSON.stringify(page_args));
			Dialog.hide();
			// app.hideMessage();
			var result = app.page_manager.click( page_name, page_args );
			if (result) {
				this.old_loc = this.loc;
				if (this.old_loc == 'init') this.old_loc = config.DefaultPage || 'Main';
				this.loc = anchor;
			}
			else {
				// current page aborted navigation -- recover current page without refresh
				this.go( this.loc );
			}
		}
		else if (sub_anchor != this.sub_anchor) {
			Debug.trace('nav', "Caught sub-anchor: " + sub_anchor);
			$P().gosub( sub_anchor );
		} // sub-anchor changed
		
		this.sub_anchor = sub_anchor;	
	},
	
	go: function(anchor, force) {
		// navigate to page
		anchor = anchor.replace(/^\#/, '');
		if (force) {
			if (anchor == this.loc) {
				this.loc = 'init';
				this.monitor();
			}
			else {
				this.loc = 'init';
				window.location.href = '#' + anchor;
			}
		}
		else {
			window.location.href = '#' + anchor;
		}
	},
	
	prev: function() {
		// return to previous page
		this.go( this.old_loc || config.DefaultPage || 'Main' );
	},
	
	refresh: function() {
		// re-nav to current page
		this.loc = 'refresh';
		this.monitor();
	},
	
	currentAnchor: function() {
		// return current page anchor
		var parts = window.location.href.split(/\#/);
		var anchor = parts[1] || '';
		var sub_anchor = '';
		
		anchor = anchor.replace(/\%7C/, '|');
		if (anchor.match(/\|(\w+)$/)) {
			// inline section anchor after article name, pipe delimited
			sub_anchor = RegExp.$1.toLowerCase();
			anchor = anchor.replace(/\|(\w+)$/, '');
		}
		
		return anchor;
	}
	
}; // Nav

//
// Page Base Class
//

Class.create( 'Page', {
	ID: '', // ID of DIV for component
	data: null,   // holds all data for freezing
	active: false, // whether page is active or not
	sidebar: true, // whether to show sidebar or not
	
	// methods
	__construct: function(config, div) {
		if (!config) return;
		
		// class constructor, import config into self
		this.data = {};
		if (!config) config = {};
		for (var key in config) this[key] = config[key];
		
		this.div = div || $('#page_' + this.ID);
		assert(this.div, "Cannot find page div: page_" + this.ID);
		
		this.tab = $('#tab_' + this.ID);
	},
	
	onInit: function() {
		// called with the page is initialized
	},
	
	onActivate: function() {
		// called when page is activated
		return true;
	},
	
	onDeactivate: function() {
		// called when page is deactivated
		return true;
	},
	
	show: function() {
		// show page
		this.div.show();
	},
	
	hide: function() {
		this.div.hide();
	},
	
	gosub: function(anchor) {
		// go to sub-anchor (article section link)
	},
	
	getPaginatedTable: function(resp, cols, data_type, callback) {
		// get html for paginated table
		// dual-calling convention: (resp, cols, data_type, callback) or (args)
		var args = null;
		if (arguments.length == 1) {
			// custom args calling convention
			args = arguments[0];
			
			// V2 API
			if (!args.resp && args.rows && args.total) {
				args.resp = {
					rows: args.rows,
					list: { length: args.total }
				};
			}
		}
		else {
			// classic calling convention
			args = {
				resp: arguments[0],
				cols: arguments[1],
				data_type: arguments[2],
				callback: arguments[3],
				limit: this.args.limit,
				offset: this.args.offset || 0
			};
		}
		
		var resp = args.resp;
		var cols = args.cols;
		var data_type = args.data_type;
		var callback = args.callback;
		var cpl = args.pagination_link || '';
		var html = '';
		
		// pagination header
		html += '<div class="pagination">';
		html += '<table cellspacing="0" cellpadding="0" border="0" width="100%"><tr>';
		
		var results = {
			limit: args.limit,
			offset: args.offset || 0,
			total: resp.list.length
		};
		
		var num_pages = Math.floor( results.total / results.limit ) + 1;
		if (results.total % results.limit == 0) num_pages--;
		var current_page = Math.floor( results.offset / results.limit ) + 1;
		
		html += '<td align="left" width="33%">';
		html += commify(results.total) + ' ' + pluralize(data_type, results.total) + ' found';
		html += '</td>';
		
		html += '<td align="center" width="34%">';
		if (num_pages > 1) html += 'Page ' + commify(current_page) + ' of ' + commify(num_pages);
		else html += '&nbsp;';
		html += '</td>';
		
		html += '<td align="right" width="33%">';
		
		if (num_pages > 1) {
			// html += 'Page: ';
			if (current_page > 1) {
				if (cpl) {
					html += '<span class="link" onMouseUp="'+cpl+'('+Math.floor((current_page - 2) * results.limit)+')">&laquo; Prev Page</span>';
				}
				else {
					html += '<a href="#' + this.ID + compose_query_string(merge_objects(this.args, {
						offset: (current_page - 2) * results.limit
					})) + '">&laquo; Prev Page</a>';
				}
			}
			html += '&nbsp;&nbsp;&nbsp;';

			var start_page = current_page - 4;
			var end_page = current_page + 5;

			if (start_page < 1) {
				end_page += (1 - start_page);
				start_page = 1;
			}

			if (end_page > num_pages) {
				start_page -= (end_page - num_pages);
				if (start_page < 1) start_page = 1;
				end_page = num_pages;
			}

			for (var idx = start_page; idx <= end_page; idx++) {
				if (idx == current_page) {
					html += '<b>' + commify(idx) + '</b>';
				}
				else {
					if (cpl) {
						html += '<span class="link" onMouseUp="'+cpl+'('+Math.floor((idx - 1) * results.limit)+')">' + commify(idx) + '</span>';
					}
					else {
						html += '<a href="#' + this.ID + compose_query_string(merge_objects(this.args, {
							offset: (idx - 1) * results.limit
						})) + '">' + commify(idx) + '</a>';
					}
				}
				html += '&nbsp;';
			}

			html += '&nbsp;&nbsp;';
			if (current_page < num_pages) {
				if (cpl) {
					html += '<span class="link" onMouseUp="'+cpl+'('+Math.floor((current_page + 0) * results.limit)+')">Next Page &raquo;</span>';
				}
				else {
					html += '<a href="#' + this.ID + compose_query_string(merge_objects(this.args, {
						offset: (current_page + 0) * results.limit
					})) + '">Next Page &raquo;</a>';
				}
			}
		} // more than one page
		else {
			html += 'Page 1 of 1';
		}
		html += '</td>';
		html += '</tr></table>';
		html += '</div>';
		
		html += '<div style="margin-top:5px;">';
		html += '<table class="data_table" width="100%">';
		html += '<tr><th>' + cols.join('</th><th>').replace(/\s+/g, '&nbsp;') + '</th></tr>';
		
		for (var idx = 0, len = resp.rows.length; idx < len; idx++) {
			var row = resp.rows[idx];
			var tds = callback(row, idx);
			if (tds) {
				html += '<tr' + (tds.className ? (' class="'+tds.className+'"') : '') + '>';
				html += '<td>' + tds.join('</td><td>') + '</td>';
				html += '</tr>';
			}
		} // foreach row
		
		if (!resp.rows.length) {
			html += '<tr><td colspan="'+cols.length+'" align="center" style="padding-top:10px; padding-bottom:10px; font-weight:bold;">';
			html += 'No '+pluralize(data_type)+' found.';
			html += '</td></tr>';
		}
		
		html += '</table>';
		html += '</div>';
		
		return html;
	},
	
	getBasicTable: function(rows, cols, data_type, callback) {
		// get html for sorted table (fake pagination, for looks only)
		var html = '';
		
		// pagination
		html += '<div class="pagination">';
		html += '<table cellspacing="0" cellpadding="0" border="0" width="100%"><tr>';
		
		html += '<td align="left" width="33%">';
		if (cols.headerLeft) html += cols.headerLeft;
		else html += commify(rows.length) + ' ' + pluralize(data_type, rows.length) + '';
		html += '</td>';
		
		html += '<td align="center" width="34%">';
			html += cols.headerCenter || '&nbsp;';
		html += '</td>';
		
		html += '<td align="right" width="33%">';
			html += cols.headerRight || 'Page 1 of 1';
		html += '</td>';
		
		html += '</tr></table>';
		html += '</div>';
		
		html += '<div style="margin-top:5px;">';
		html += '<table class="data_table" width="100%">';
		html += '<tr><th style="white-space:nowrap;">' + cols.join('</th><th style="white-space:nowrap;">') + '</th></tr>';
		
		for (var idx = 0, len = rows.length; idx < len; idx++) {
			var row = rows[idx];
			var tds = callback(row, idx);
			if (tds.insertAbove) html += tds.insertAbove;
			html += '<tr' + (tds.className ? (' class="'+tds.className+'"') : '') + '>';
			html += '<td>' + tds.join('</td><td>') + '</td>';
			html += '</tr>';
		} // foreach row
		
		if (!rows.length) {
			html += '<tr><td colspan="'+cols.length+'" align="center" style="padding-top:10px; padding-bottom:10px; font-weight:bold;">';
			html += 'No '+pluralize(data_type)+' found.';
			html += '</td></tr>';
		}
		
		html += '</table>';
		html += '</div>';
		
		return html;
	}
	
} ); // class Page

//
// Page Manager
//

Class.create( 'PageManager', {
	// 'PageManager' class handles all virtual pages in the application
	
	// member variables
	pages: null, // array of pages
	current_page_id: '', // current page ID
	
	// methods
	__construct: function(page_list) {
		// class constructor, create all pages
		// page_list should be array of components from master config
		// each one should have at least a 'ID' parameter
		// anything else is copied into object verbatim
		this.pages = [];
		this.page_list = page_list;
		
		for (var idx = 0, len = page_list.length; idx < len; idx++) {
			Debug.trace( 'page', "Initializing page: " + page_list[idx].ID );
			assert(Page[ page_list[idx].ID ], "Page class not found: Page." + page_list[idx].ID);
			
			var page = new Page[ page_list[idx].ID ]( page_list[idx] );
			page.args = {};
			page.onInit();
			this.pages.push(page);
			
			$('#tab_'+page.ID).click( function(event) {
				// console.log( this );
				// app.page_manager.click( this._page_id );
				Nav.go( this._page_id );
			} )[0]._page_id = page.ID;
		}
	},
	
	find: function(id) {
		// locate page by ID (i.e. Plugin Name)
		var page = find_object( this.pages, { ID: id } );
		if (!page) Debug.trace('PageManager', "Could not find page: " + id);
		return page;
	},
	
	activate: function(id, old_id, args) {
		// send activate event to page by id (i.e. Plugin Name)
		$('#page_'+id).show();
		$('#tab_'+id).removeClass('inactive').addClass('active');
		var page = this.find(id);
		page.active = true;
		
		if (!args) args = {};
		
		// if we are navigating here from a different page, AND the new sub mismatches the old sub, clear the page html
		var new_sub = args.sub || '';
		if (old_id && (id != old_id) && (typeof(page._old_sub) != 'undefined') && (new_sub != page._old_sub) && page.div) {
			page.div.html('');
		}
						
		var result = page.onActivate.apply(page, [args]);
		if (typeof(result) == 'boolean') return result;
		else throw("Page " + id + " onActivate did not return a boolean!");
	},
	
	deactivate: function(id, new_id) {
		// send deactivate event to page by id (i.e. Plugin Name)
		var page = this.find(id);
		var result = page.onDeactivate(new_id);
		if (result) {
			$('#page_'+id).hide();
			$('#tab_'+id).removeClass('active').addClass('inactive');
			// $('#d_message').hide();
			page.active = false;
			
			// if page has args.sub, save it for clearing html on reactivate, if page AND sub are different
			if (page.args) page._old_sub = page.args.sub || '';
		}
		return result;
	},
	
	click: function(id, args) {
		// exit current page and enter specified page
		Debug.trace('page', "Switching pages to: " + id);
		var old_id = this.current_page_id;
		if (this.current_page_id) {
			var result = this.deactivate( this.current_page_id, id );
			if (!result) return false; // current page said no
		}
		this.current_page_id = id;
		this.old_page_id = old_id;
		
		window.scrollTo( 0, 0 );
		
		var result = this.activate(id, old_id, args);
		if (!result) {
			// new page has rejected activation, probably because a login is required
			// un-hide previous page div, but don't call activate on it
			$('#page_'+id).hide();
			this.current_page_id = '';
		}
		
		return true;
	}
	
} ); 


var Dialog = {
	
	active: false,
	clickBlock: false,
	
	showAuto: function(title, inner_html, click_block) {
		// measure size of HTML to create correctly positioned dialog
		var temp = $('<div/>').css({
			position: 'absolute',
			visibility: 'hidden'
		}).html(inner_html).appendTo('body');
		
		var width = temp.width();
		var height = temp.height();
		temp.remove();
		
		this.show( width, height, title, inner_html, click_block );
	},
	
	autoResize: function() {
		// automatically resize dialog to match changed content size
		var temp = $('<div/>').css({
			position: 'absolute',
			visibility: 'hidden'
		}).html( $('#dialog_main').html() ).appendTo('body');
		
		var width = temp.width();
		var height = temp.height();
		temp.remove();
		
		var size = get_inner_window_size();
		var x = Math.floor( (size.width / 2) - ((width + 0) / 2) );
		var y = Math.floor( ((size.height / 2) - (height / 2)) * 0.75 );
		
		$('#dialog_main').css({
			width: '' + width + 'px',
			height: '' + height + 'px'
		});
		$('#dialog_container').css({
			left: '' + x + 'px',
			top: '' + y + 'px'
		});
	},
	
	show: function(width, height, title, inner_html, click_block) {
		// show dialog
		this.clickBlock = click_block || false;
		var body = document.getElementsByTagName('body')[0];
		
		// build html for dialog
		var html = '';
		if (title) {
			html += '<div class="tab_bar" style="width:'+width+'px;">';
				html += '<div class="tab active"><span class="content">'+title+'</span></div>';
			html += '</div>';
		}
		html += '<div id="dialog_main" style="width:auto; height:auto;">';
			html += inner_html;
		html += '</div>';
		
		var size = get_inner_window_size();
		var x = Math.floor( (size.width / 2) - ((width + 0) / 2) );
		var y = Math.floor( ((size.height / 2) - (height / 2)) * 0.75 );
		
		if ($('#dialog_overlay').length) {
			$('#dialog_overlay').stop().remove();
		}
		
		var overlay = document.createElement('div');
		overlay.id = 'dialog_overlay';
		overlay.style.opacity = 0;
		body.appendChild(overlay);
		$(overlay).fadeTo( 500, 0.75 ).click(function() {
			if (!Dialog.clickBlock) Dialog.hide();
		});
		
		if ($('#dialog_container').length) {
			$('#dialog_container').stop().remove();
		}
		
		var container = document.createElement('div');
		container.id = 'dialog_container';
		container.style.opacity = 0;
		container.style.left = '' + x + 'px';
		container.style.top = '' + y + 'px';
		container.innerHTML = html;
		body.appendChild(container);
		$(container).fadeTo( 250, 1.0 );
		
		this.active = true;
	},
	
	hide: function() {
		// hide dialog
		if (this.active) {
			$('#dialog_container').stop().fadeOut( 250, function() { $(this).remove(); } );
			$('#dialog_overlay').stop().fadeOut( 500, function() { $(this).remove(); } );
			this.active = false;
		}
	},
	
	showProgress: function(msg) {
		// show simple progress dialog (unspecified duration)
		var html = '';
		html += '<table width="300" height="120" cellspacing="0" cellpadding="0"><tr><td width="300" height="120" align="center" valign="center">';
		html += '<img src="images/loading.gif" width="32" height="32"/><br/><br/>';
		html += '<span class="label" style="padding-top:5px">' + msg + '</span>';
		html += '</td></tr></table>';
		this.show( 300, 120, '', html );
	}
	
};

// Base App Framework

var app = {
	
	username: '',
	cacheBust: hires_time_now(),
	proto: location.protocol.match(/^https/i) ? 'https://' : 'http://',
	secure: !!location.protocol.match(/^https/i),
	retina: (window.devicePixelRatio > 1),
	base_api_url: '/api',
	plain_text_post: false,
	prefs: {},
	
	init: function() {
		// override this in your app.js
	},
	
	extend: function(obj) {
		// extend app object with another
		for (var key in obj) this[key] = obj[key];
	},
	
	setAPIBaseURL: function(url) {
		// set the API base URL (commands are appended to this)
		this.base_api_url = url;
	},
	
	setWindowTitle: function(title) {
		// set the current window title, includes app name
		document.title = title + ' | ' + this.name;
	},
	
	showTabBar: function(visible) {
		// show or hide tab bar
		if (visible) $('.tab_bar').show();
		else $('.tab_bar').hide();
	},
	
	updateHeaderInfo: function() {
		// update top-right display
		// override this function in app
	},
	
	getUserAvatarURL: function() {
		// get URL to user's avatar using Gravatar.com service
		var size = 0;
		var email = '';
		if (arguments.length == 2) {
			email = arguments[0];
			size = arguments[1];
		}
		else if (arguments.length == 1) {
			email = this.user.email;
			size = arguments[0];
		}
		
		// user may have custom avatar
		if (this.user && this.user.avatar) {
			// convert to protocol-less URL
			return this.user.avatar.replace(/^\w+\:/, '');
		}
		
		return '//en.gravatar.com/avatar/' + hex_md5( email.toLowerCase() ) + '.jpg?s=' + size + '&d=mm';
	},
	
	doMyAccount: function() {
		// nav to the my account page
		Nav.go('MyAccount');
	},
	
	doUserLogin: function(resp) {
		// user login, called from login page, or session recover
		app.username = resp.username;
		app.user = resp.user;
		
		app.setPref('username', resp.username);
		app.setPref('session_id', resp.session_id);
		
		this.updateHeaderInfo();
		
		if (this.isAdmin()) $('#tab_Admin').show();
		else $('#tab_Admin').hide();
	},
	
	doUserLogout: function(bad_cookie) {
		// log user out and redirect to login screen
		if (!bad_cookie) {
			// user explicitly logging out
			app.showProgress(1.0, "Logging out...");
			app.setPref('username', '');
		}
		
		app.api.post( 'user/logout', {
			session_id: app.getPref('session_id')
		}, 
		function(resp, tx) {
			app.hideProgress();
			
			delete app.user;
			delete app.username;
			delete app.user_info;
			
			app.setPref('session_id', '');
			
			$('#d_header_user_container').html( '' );
			
			Debug.trace("User session cookie was deleted, redirecting to login page");
			Nav.go('Login');
			
			setTimeout( function() {
				if (bad_cookie) app.showMessage('error', "Your session has expired.  Please log in again.");
				else app.showMessage('success', "You were logged out successfully.");
			}, 150 );
			
			$('#tab_Admin').hide();
		} );
	},
	
	isAdmin: function() {
		// return true if user is logged in and admin, false otherwise
		return( app.user && app.user.privileges && app.user.privileges.admin );
	},
	
	handleResize: function() {
		// called when window resizes
		if (this.page_manager && this.page_manager.current_page_id) {
			var id = this.page_manager.current_page_id;
			var page = this.page_manager.find(id);
			if (page && page.onResize) page.onResize( get_inner_window_size() );
		}
		
		// also handle sending resize events at a 250ms delay
		// so some pages can perform a more expensive refresh at a slower interval
		if (!this.resize_timer) {
			this.resize_timer = setTimeout( this.handleResizeDelay.bind(this), 250 );
		}
	},
	
	handleResizeDelay: function() {
		// called 250ms after latest resize event
		this.resize_timer = null;
		
		if (this.page_manager && this.page_manager.current_page_id) {
			var id = this.page_manager.current_page_id;
			var page = this.page_manager.find(id);
			if (page && page.onResizeDelay) page.onResizeDelay( get_inner_window_size() );
		}
	},
	
	handleUnload: function() {
		// called just before user navs off
		if (this.page_manager && this.page_manager.current_page_id && $P && $P() && $P().onBeforeUnload) {
			var result = $P().onBeforeUnload();
			if (result) {
				(e || window.event).returnValue = result; //Gecko + IE
				return result; // Webkit, Safari, Chrome etc.
			}
		}
	},
	
	doError: function(msg, lifetime) {
		// show an error message at the top of the screen
		// and hide the progress dialog if applicable
		Debug.trace("ERROR: " + msg);
		this.showMessage( 'error', msg, lifetime );
		if (this.progress) this.hideProgress();
		return null;
	},
	
	badField: function(id, msg) {
		// mark field as bad
		if (id.match(/^\w+$/)) id = '#' + id;
		$(id).removeClass('invalid').width(); // trigger reflow to reset css animation
		$(id).addClass('invalid');
		try { $(id).focus(); } catch (e) {;}
		if (msg) return this.doError(msg);
		else return false;
	},
	
	clearError: function(animate) {
		// clear last error
		app.hideMessage(animate);
		$('.invalid').removeClass('invalid');
	},
	
	showMessage: function(type, msg, lifetime) {
		// show success, warning or error message
		// Dialog.hide();
		var icon = '';
		switch (type) {
			case 'success': icon = 'check-circle'; break;
			case 'warning': icon = 'exclamation-circle'; break;
			case 'error': icon = 'exclamation-triangle'; break;
		}
		if (icon) {
			msg = '<i class="fa fa-'+icon+' fa-lg" style="transform-origin:50% 50%; transform:scale(1.25); -webkit-transform:scale(1.25);">&nbsp;&nbsp;&nbsp;</i>' + msg;
		}
		
		$('#d_message_inner').html( msg );
		$('#d_message').hide().removeClass().addClass('message').addClass(type).show(250);
		
		if (this.messageTimer) clearTimeout( this.messageTimer );
		if ((type == 'success') || lifetime) {
			if (!lifetime) lifetime = 8;
			this.messageTimer = setTimeout( function() { app.hideMessage(500); }, lifetime * 1000 );
		}
	},
	
	hideMessage: function(animate) {
		if (animate) $('#d_message').hide(animate);
		else $('#d_message').hide();
	},
	
	api: {
		request: function(url, args, callback, errorCallback) {
			// send AJAX request to server using jQuery
			var headers = {};
			
			// inject session id into headers, unless app is using plain_text_post
			if (app.getPref('session_id') && !app.plain_text_post) {
				headers['X-Session-ID'] = app.getPref('session_id');
			}
			
			args.context = this;
			args.url = url;
			args.dataType = 'text'; // so we can parse the response json ourselves
			args.timeout = 1000 * 10; // 10 seconds
			args.headers = headers;
			
			$.ajax(args).done( function(text) {
				// parse JSON and fire callback
				Debug.trace( 'api', "Received response from server: " + text );
				var resp = null;
				try { resp = JSON.parse(text); }
				catch (e) {
					// JSON parse error
					var desc = "JSON Error: " + e.toString();
					if (errorCallback) errorCallback({ code: 500, description: desc });
					else app.doError(desc);
				}
				// success, but check json for server error code
				if (resp) {
					if (('code' in resp) && (resp.code != 0)) {
						// an error occurred within the JSON response
						// session errors are handled specially
						if (resp.code == 'session') app.doUserLogout(true);
						else if (errorCallback) errorCallback(resp);
						else app.doError("Error: " + resp.description);
					}
					else if (callback) callback(resp);
				}
			} )
			.fail( function(xhr, status, err) {
				// XHR or HTTP error
				var code = xhr.status || 500;
				var desc = err.toString() || status.toString();
				switch (desc) {
					case 'timeout': desc = "The request timed out.  Please try again."; break;
					case 'error': desc = "An unknown network error occurred.  Please try again."; break;
				}
				Debug.trace( 'api', "Network Error: " + code + ": " + desc );
				if (errorCallback) errorCallback({ code: code, description: desc });
				else app.doError( "Network Error: " + code + ": " + desc );
			} );
		},
		
		post: function(cmd, params, callback, errorCallback) {
			// send AJAX POST request to server using jQuery
			var url = cmd;
			if (!url.match(/^(\w+\:\/\/|\/)/)) url = app.base_api_url + "/" + cmd;
			
			if (!params) params = {};
			
			// inject session in into json if submitting as plain text (cors preflight workaround)
			if (app.getPref('session_id') && app.plain_text_post) {
				params['session_id'] = app.getPref('session_id');
			}
			
			var json_raw = JSON.stringify(params);
			Debug.trace( 'api', "Sending HTTP POST to: " + url + ": " + json_raw );
			
			this.request(url, {
				type: "POST",
				data: json_raw,
				contentType: app.plain_text_post ? 'text/plain' : 'application/json'
			}, callback, errorCallback);
		},
		
		get: function(cmd, query, callback, errorCallback) {
			// send AJAX GET request to server using jQuery
			var url = cmd;
			if (!url.match(/^(\w+\:\/\/|\/)/)) url = app.base_api_url + "/" + cmd;
			
			if (!query) query = {};
			query.cachebust = app.cacheBust;
			url += compose_query_string(query);
			
			Debug.trace( 'api', "Sending HTTP GET to: " + url );
			
			this.request(url, {
				type: "GET"
			}, callback, errorCallback);
		}
	}, // api
	
	getPref: function(key) {
		// get pref using html5 localStorage
		if (window.localStorage) return localStorage[key];
		else return this.prefs[key];
	},
	
	setPref: function(key, value) {
		if (window.localStorage) localStorage[key] = value;
		else prefs[key] = value;
	},
	
	hideProgress: function() {
		// hide progress dialog
		Dialog.hide();
		delete app.progress;
	},
	
	showProgress: function(counter, title) {
		// show or update progress bar
		if (!$('#d_progress_bar').length) {
			// no progress dialog is active, so set it up
			if (!counter) counter = 0;
			if (counter < 0) counter = 0;
			if (counter > 1) counter = 1;
			var cx = Math.floor( counter * 196 );
			
			var html = '';
			html += '<div class="dialog_simple dialog_shadow">';
			// html += '<center>';
			// html += '<div class="loading" style="width:32px; height:32px; margin:0 auto 10px auto;"></div>';
			html += '<div id="d_progress_title" class="dialog_subtitle" style="text-align:center; position:relative; top:-5px;">' + title + '</div>';
			
			var extra_classes = '';
			if (counter == 1.0) extra_classes = 'indeterminate';
			
			html += '<div id="d_progress_bar_cont" class="progress_bar_container '+extra_classes+'" style="width:196px; margin:0 auto 0 auto;">';
				html += '<div id="d_progress_bar" class="progress_bar_inner" style="width:'+cx+'px;"></div>';
			html += '</div>';
			
			// html += '</center>';
			html += '</div>';
			
			app.hideMessage();
			Dialog.show(275, 100, "", html, true);
			
			app.progress = {
				start_counter: counter,
				counter: counter,
				counter_max: 1,
				start_time: hires_time_now(),
				last_update: hires_time_now(),
				title: title
			};
		}
		else if (app.progress) {
			// dialog is active, so update existing elements
			var now = hires_time_now();
			var cx = Math.floor( counter * 196 );
			$('#d_progress_bar').css( 'width', '' + cx + 'px' );
			
			var prog_cont = $('#d_progress_bar_cont');
			if ((counter == 1.0) && !prog_cont.hasClass('indeterminate')) prog_cont.addClass('indeterminate');
			else if ((counter < 1.0) && prog_cont.hasClass('indeterminate')) prog_cont.removeClass('indeterminate');
			
			if (title) app.progress.title = title;
			$('#d_progress_title').html( app.progress.title );
			
			app.progress.last_update = now;
			app.progress.counter = counter;
		}
	},
	
	showDialog: function(title, inner_html, buttons_html) {
		// show dialog using our own look & feel
		var html = '';
		html += '<div class="dialog_title">' + title + '</div>';
		html += '<div class="dialog_content">' + inner_html + '</div>';
		html += '<div class="dialog_buttons">' + buttons_html + '</div>';
		Dialog.showAuto( "", html );
	},
	
	hideDialog: function() {
		Dialog.hide();
	},
	
	confirm: function(title, html, ok_btn_label, callback) {
		// show simple OK / Cancel dialog with custom text
		// fires callback with true (OK) or false (Cancel)
		if (!ok_btn_label) ok_btn_label = "OK";
		this.confirm_callback = callback;
		
		var inner_html = "";
		inner_html += '<div class="confirm_container">'+html+'</div>';
		
		var buttons_html = "";
		buttons_html += '<center><table><tr>';
			buttons_html += '<td><div class="button" style="width:100px; font-weight:normal;" onMouseUp="app.confirm_click(false)">Cancel</div></td>';
			buttons_html += '<td width="60">&nbsp;</td>';
			buttons_html += '<td><div class="button" style="width:100px;" onMouseUp="app.confirm_click(true)">'+ok_btn_label+'</div></td>';
		buttons_html += '</tr></table></center>';
		
		this.showDialog( title, inner_html, buttons_html );
		
		// special mode for key capture
		Dialog.active = 'confirmation';
	},
	
	confirm_click: function(result) {
		// user clicked OK or Cancel in confirmation dialog, fire callback
		// caller MUST deal with Dialog.hide() if result is true
		if (this.confirm_callback) {
			this.confirm_callback(result);
			if (!result) Dialog.hide();
		}
	},
	
	confirm_key: function(event) {
		// handle keydown with active confirmation dialog
		if (Dialog.active !== 'confirmation') return;
		if ((event.keyCode != 13) && (event.keyCode != 27)) return;
		
		// skip enter check if textarea is active
		if (document.activeElement && (event.keyCode == 13)) {
			if ($(document.activeElement).prop('type') == 'textarea') return;
		}
		
		event.stopPropagation();
		event.preventDefault();
		
		if (event.keyCode == 13) this.confirm_click(true);
		else if (event.keyCode == 27) this.confirm_click(false);
	},
	
	get_base_url: function() {
		return app.proto + location.hostname + '/';
	},
	
	setTheme: function(theme) {
		// toggle light/dark theme
		if (theme == 'dark') {
			$('body').addClass('dark');
			$('#d_theme_ctrl').html( '<i class="fa fa-moon-o fa-lg">&nbsp;</i>Dark' );
			this.setPref('theme', 'dark');
		}
		else {
			$('body').removeClass('dark');
			$('#d_theme_ctrl').html( '<i class="fa fa-lightbulb-o fa-lg">&nbsp;</i>Light' );
			this.setPref('theme', 'light');
		}
		
		if (this.onThemeChange) this.onThemeChange(theme);
	},
	
	initTheme: function() {
		// set theme to user's preference
		if (!this.getPref('theme')) {
			// brand new user: try to guess theme using media query
			if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
				this.setPref('theme', 'dark');
			}
		}
		this.setTheme( this.getPref('theme') || 'light' );
	},
	
	toggleTheme: function() {
		// toggle light/dark theme
		if (this.getPref('theme') == 'dark') this.setTheme('light');
		else this.setTheme('dark');
	}
	
}; // app object

function get_form_table_row() {
	// Get HTML for formatted form table row (label and content).
	var tr_class = '';
	var left = '';
	var right = '';
	if (arguments.length == 3) {
		tr_class = arguments[0]; left = arguments[1]; right = arguments[2];
	}
	else {
		left = arguments[0]; right = arguments[1];
	}
	
	left = left.replace(/\s/g, '&nbsp;').replace(/\:$/, '');
	if (left) left += ':'; else left = '&nbsp;';
	
	var html = '';
	html += '<tr class="'+tr_class+'">';
		html += '<td align="right" class="table_label">'+left+'</td>';
		html += '<td align="left" class="table_value">';
			html += '<div>'+right+'</div>';
		html += '</td>';
	html += '</tr>';
	return html;
};

function get_form_table_caption() {
	// Get HTML for form table caption (takes up a row).
	var tr_class = '';
	var cap = '';
	if (arguments.length == 2) {
		tr_class = arguments[0]; cap = arguments[1];
	}
	else {
		cap = arguments[0];
	}
	
	var html = '';
	html += '<tr class="'+tr_class+'">';
		html += '<td>&nbsp;</td>';
		html += '<td align="left">';
			html += '<div class="caption">'+cap+'</div>';
		html += '</td>';
	html += '</tr>';
	return html;
};

function get_form_table_spacer() {
	// Get HTML for form table spacer (takes up a row).
	var tr_class = '';
	var extra_classes = '';
	if (arguments.length == 2) {
		tr_class = arguments[0]; extra_classes = arguments[1];
	}
	else {
		extra_classes = arguments[0];
	}
	
	var html = '';
	html += '<tr class="'+tr_class+'"><td colspan="2"><div class="table_spacer '+extra_classes+'"></div></td></tr>';
	return html;
};

function $P(id) {
	// shortcut for page_manager.find(), also defaults to current page
	if (!id) id = app.page_manager.current_page_id;
	var page = app.page_manager.find(id);
	assert( !!page, "Failed to locate page: " + id );
	return page;
};

var Debug = {
	backlog: [],
	
	dump: function() {
		// dump backlog to console
		for (var idx = 0, len = this.backlog.length; idx < len; idx++) {
			console.log( this.backlog[idx] );
		}
	},
	
	trace: function(cat, msg) {
		// trace one line to console, or store in backlog
		if (arguments.length == 1) { msg = cat; cat = 'debug'; }
		if (window.console && console.log && window.config && config.debug) {
			console.log( cat + ': ' + msg );
		}
		else {
			this.backlog.push( hires_time_now() + ': ' + cat + ': ' + msg );
			if (this.backlog.length > 100) this.backlog.shift();
		}
	}
};

$(document).ready(function() {
	app.init();
});

window.addEventListener( "keydown", function(event) {
	app.confirm_key(event);
}, false );

window.addEventListener( "resize", function() {
	app.handleResize();
}, false );

window.addEventListener("beforeunload", function (e) {
	return app.handleUnload();
}, false );

if (!window.app) throw new Error("App Framework is not present.");

app.extend({
	
	name: '',
	preload_images: ['loading.gif'],
	plain_text_post: false,
	default_prefs: {
		graph_size: 'half',
		ov_graph_size: 'third',
		auto_refresh: '1', // localStorage is ALWAYS STRINGS (ugh)
		annotations: '1'
	},
	debug_cats: { 
		all: 1, 
		api: false
	},
	
	receiveConfig: function(resp) {
		// receive config from server
		delete resp.code;
		window.config = resp.config;

		
		this.initTheme();
		
		for (var key in resp) {
			this[key] = resp[key];
		}
		
		// allow visible app name to be changed in config
		this.name = config.name;
		$('#d_header_title').html( '<b>' + this.name + '</b>' );
		
		this.config.Page = [
			{ ID: 'Home' },
			{ ID: 'Group' },
			{ ID: 'Server' },
			{ ID: 'Snapshot' },
			{ ID: 'Login' },
			{ ID: 'MyAccount' },
			{ ID: 'Admin' }
		];
		this.config.DefaultPage = 'Home';
		
		// did we try to init and fail?  if so, try again now
		if (this.initReady) {
			this.hideProgress();
			delete this.initReady;
			this.init();
		}
	},
	
	init: function() {
		// initialize application
		if (this.abort) return; // fatal error, do not initialize app
		
		if (!this.config) {
			// must be in master server wait loop
			this.initReady = true;
			return;
		}
		
		if (!this.config.groups || !this.config.groups.length) return app.doError("FATAL: No groups defined in configuration.");
		if (!this.config.monitors || !this.config.monitors.length) return app.doError("FATAL: No monitors defined in configuration.");
		
		// preload a few essential images
		for (var idx = 0, len = this.preload_images.length; idx < len; idx++) {
			var filename = '' + this.preload_images[idx];
			var img = new Image();
			img.src = '/images/'+filename;
		}
		
		// populate prefs for first time user
		for (var key in this.default_prefs) {
			if (!(key in window.localStorage)) {
				window.localStorage[key] = this.default_prefs[key];
			}
		}
		
		// precompile regexpes
		this.hostnameStrip = new RegExp( config.hostname_display_strip );
		
		// pop version into footer
		$('#d_footer_version').html( "Version " + this.version || 0 );
		
		// some css munging for safari
		var ua = navigator.userAgent;
		if (ua.match(/Safari/) && !ua.match(/(Chrome|Opera)/)) {
			$('body').addClass('safari');
			this.safari = true;
		}
		
		// listen for events
		window.addEventListener( "scroll", debounce(this.onScrollDebounce.bind(this), 50), false );
		window.addEventListener( "focus", this.onFocus.bind(this), false );
		$('#fe_ctrl_filter').on( 'keyup', debounce(this.onFilterKeyUp.bind(this), 50) );
		
		// init controls
		this.initControlMenus();
		
		// init "jump to" menus
		this.initJumpMenus();
		
		// init page manager and launch current page
		this.page_manager = new PageManager( always_array(config.Page) );
		
		// wait for our fonts to load (because we use them in canvases)
		onfontsready(['Lato', 'LatoBold'], function() {
			if (!Nav.inited) Nav.init();
			
			// start tick timer
			app.tickTimer = setInterval( app.tick.bind(app), 1000 );
		},
		{
			timeoutAfter: 3000,
			onTimeout: function() {
				Debug.trace('error', "Fonts timed out, loading app anyway");
				if (!Nav.inited) Nav.init();
			}
		});
	},
	
	initControlMenus: function() {
		// populate control strip menus (dates, groups)
		var dargs = get_date_args( new Date() );
		if (!config.first_year) config.first_year = dargs.year;
		var first_year = config.first_year;
		var old_year = $('#fe_ctrl_year').val();
		
		$('#fe_ctrl_year').empty();
		for (var year = first_year; year <= dargs.year; year++) {
			$('#fe_ctrl_year').append( '<option value="' + year + '">' + year + '</option>' );
		}
		if (old_year) $('#fe_ctrl_year').val( old_year );
		
		var old_group = $('#fe_ctrl_group').val();
		$('#fe_ctrl_group').empty();
		
		this.config.groups.sort( function(a, b) {
			return a.id.localeCompare( b.id );
		} );
		
		this.config.groups.forEach( function(group_def) {
			$('#fe_ctrl_group').append( '<option value="' + group_def.id + '">' + group_def.title + '</option>' );
		});
		if (old_group) $('#fe_ctrl_group').val( old_group );
	},
	
	getRecentServerMenuOptionsHTML: function() {
		// get nice server list with sorted groups (and sorted servers in groups)
		var self = this;
		var menu_groups = {};
		var other_hostnames = [];
		
		// jump to server menu
		for (var hostname in this.recent_hostnames) {
			var value = this.recent_hostnames[hostname];
			if (value === 1) {
				// standard host, need to match group
				var group_def = this.findGroupFromHostname( hostname );
				if (group_def) {
					if (!menu_groups[group_def.id]) menu_groups[group_def.id] = [];
					menu_groups[group_def.id].push( hostname );
				}
				else other_hostnames.push(hostname);
			}
			else {
				// auto-scale host, has group embedded as value
				if (!menu_groups[value]) menu_groups[value] = [];
				menu_groups[value].push( hostname );
			}
		}
		
		var num_menu_groups = num_keys(menu_groups);
		var menu_html = '';
		
		hash_keys_to_array(menu_groups).sort().forEach( function(group_id, idx) {
			var group_def = find_object( config.groups, { id: group_id } );
			if (!group_def) return;
			var group_hostnames = menu_groups[group_id].sort();
			
			if (num_menu_groups > 1) {
				if (idx > 0) menu_html += '<option value="" disabled></option>';
				menu_html += '<optgroup label="' + group_def.title + '">';
			}
			menu_html += group_hostnames.map( function(hostname) {
				return '<option value="' + hostname + '">' + self.formatHostname(hostname) + '</option>';
			} ).join('');
			if (num_menu_groups > 1) {
				menu_html += '</optgroup>';
			}
		});
		
		if (other_hostnames.length) {
			if (num_menu_groups > 1) {
				menu_html += '<option value="" disabled></option>';
				menu_html += '<optgroup label="(Unassigned)">';
			}
			menu_html += other_hostnames.map( function(hostname) {
				return '<option value="' + hostname + '">' + self.formatHostname(hostname) + '</option>';
			} ).join('');
			if (num_menu_groups > 1) {
				menu_html += '</optgroup>';
			}
		}
		
		return menu_html;
	},
	
	initJumpMenus: function() {
		// populate tab bar "jump to" menus with servers, groups
		var self = this;
		
		var menu_html = '';
		menu_html += '<option value="" disabled>Jump to Server</option>';
		var temp_html = this.getRecentServerMenuOptionsHTML();
		if (temp_html.match(/<optgroup/)) menu_html += '<option value="" disabled></option>';
		menu_html += temp_html;
		$('#fe_jump_to_server').empty().append( menu_html ).val('');
		
		// jump to group menu
		$('#fe_jump_to_group').empty().append(
			'<option value="" disabled>Jump to Group</option>'
		);
		
		this.config.groups.sort( function(a, b) {
			return a.id.localeCompare( b.id );
		} );
		
		this.config.groups.forEach( function(group_def) {
			$('#fe_jump_to_group').append( '<option value="' + group_def.id + '">' + group_def.title + '</option>' );
		});
		$('#fe_jump_to_group').val('');
	},
	
	updateRecentHostnames: function(hostnames) {
		// merge in hostnames (presumably from api/app/contrib) into recent list
		// if any additions came in, redraw jump menu
		var need_redraw = false;
		
		for (var hostname in hostnames) {
			if (!(hostname in this.recent_hostnames)) {
				this.recent_hostnames[hostname] = hostnames[hostname];
				need_redraw = true;
			}
		}
		
		if (need_redraw) this.initJumpMenus();
	},
	
	updateHeaderInfo: function() {
		// update top-right display
		var theme_ctrl = (app.getPref('theme') == 'dark') ? 
			'<i class="fa fa-moon-o fa-lg">&nbsp;</i>Dark' : 
			'<i class="fa fa-lightbulb-o fa-lg">&nbsp;</i>Light';
		
		var alert_ctrl = (config.state.alert_snooze && (config.state.alert_snooze > time_now())) ? 
			'<i class="mdi mdi-bell-off mdi-lg">&nbsp;</i>Snooze' : 
			'<i class="mdi mdi-bell mdi-lg">&nbsp;</i>Active';
		
		var html = '';
		html += '<div class="header_divider right" style="margin-right:0;"></div>';
		html += '<div class="header_option logout right" onMouseUp="app.doUserLogout()"><i class="fa fa-power-off fa-lg">&nbsp;</i>Logout</div>';
		html += '<div class="header_divider right"></div>';
		html += '<div id="d_theme_ctrl" class="header_option right" onMouseUp="app.toggleTheme()" title="Toggle Light/Dark Theme">' + theme_ctrl + '</div>';
		if (this.isAdmin()) {
			html += '<div class="header_divider right"></div>';
			html += '<div id="d_alert_ctrl" class="header_option right" onMouseUp="app.editAlertSnooze()" title="Alert Snooze...">' + alert_ctrl + '</div>';
		}
		html += '<div class="header_divider right"></div>';
		html += '<div id="d_header_user_bar" class="right" style="background-image:url(' + this.getUserAvatarURL( this.retina ? 64 : 32 ) + ')" onMouseUp="app.doMyAccount()">' + (this.user.full_name || this.username).replace(/\s+.+$/, '') + '</div>';
		$('#d_header_user_container').html( html );
	},
	
	getTimeMenuItem: function(secs) {
		// get nice time menu item given seconds
		return [ secs, get_text_from_seconds(secs, false, true) ];
	},
	
	editAlertSnooze: function() {
		// snooze alerts, or cancel snooze
		var self = this;
		var html = '';
		var snooze_sel = 0;
		var dialog_icon = '';
		
		var snooze_items = [
			[0, "(Disable Snooze)"],
			this.getTimeMenuItem( 60 * 5 ),
			this.getTimeMenuItem( 60 * 10 ),
			this.getTimeMenuItem( 60 * 15 ),
			this.getTimeMenuItem( 60 * 30 ),
			this.getTimeMenuItem( 60 * 45 ),
			this.getTimeMenuItem( 3600 ),
			this.getTimeMenuItem( 3600 * 2 ),
			this.getTimeMenuItem( 3600 * 3 ),
			this.getTimeMenuItem( 3600 * 6 ),
			this.getTimeMenuItem( 3600 * 12 ),
			this.getTimeMenuItem( 3600 * 18 ),
			this.getTimeMenuItem( 86400 ),
			this.getTimeMenuItem( 86400 * 2 ),
			this.getTimeMenuItem( 86400 * 3 ),
			this.getTimeMenuItem( 86400 * 7 ),
			this.getTimeMenuItem( 86400 * 15 ),
			this.getTimeMenuItem( 86400 * 30 ),
			this.getTimeMenuItem( 86400 * 30 * 2 ),
			this.getTimeMenuItem( 86400 * 30 * 3 ),
			this.getTimeMenuItem( 86400 * 30 * 6 ),
			this.getTimeMenuItem( 86400 * 365 )
		];
		
		if (config.state.alert_snooze && (config.state.alert_snooze > time_now())) {
			// snooze is currently enabled
			html += '<div style="font-size:12px; margin-bottom:20px;">Alerts are currently <b>snoozed</b>, and will be until <b>' + get_nice_date_time(config.state.alert_snooze, false, false) + '</b> (approximately ' + get_text_from_seconds(config.state.alert_snooze - time_now(), false, true) + ' from now).  Use the menu below to reset the snooze timer, or cancel it and reactivate all alerts.</div>';
			snooze_sel = 0;
			dialog_icon = 'mdi mdi-bell-off';
		}
		else {
			// snooze is disabled
			html += '<div style="font-size:12px; margin-bottom:20px;">Alerts are currently <b>active</b>.  Use the menu below to optionally set a snooze timer, which will disable alert notifications for a specific amount of time.</div>';
			snooze_sel = 3600;
			dialog_icon = 'mdi mdi-bell';
		}
		
		html += '<center><table>' + 
			// get_form_table_spacer() + 
			get_form_table_row('Snooze For:', '<select id="fe_alert_snooze">' + render_menu_options(snooze_items, snooze_sel) + '</select>') + 
			get_form_table_caption("Select the amount of time to snooze alerts for.") + 
		'</table></center>';
		
		app.confirm( '<i class="' + dialog_icon + '">&nbsp;</i>Alert Snooze', html, "Set Snooze", function(result) {
			app.clearError();
			
			if (result) {
				var alert_snooze = parseInt( $('#fe_alert_snooze').val() );
				config.state.alert_snooze = alert_snooze;
				if (alert_snooze) config.state.alert_snooze += time_now(); // future date to wake up at
				var new_state = { alert_snooze: config.state.alert_snooze };
				Dialog.hide();
				
				app.api.post( 'app/update_state', new_state, function(resp) {
					
					if (alert_snooze) {
						app.showMessage('success', "Alerts will be snoozed for " + get_text_from_seconds(alert_snooze, false, true) + ".");
						$('#d_alert_ctrl').html( '<i class="mdi mdi-bell-off mdi-lg">&nbsp;</i>Snooze' );
					}
					else {
						app.showMessage('success', "Alerts have been reactivated.");
						$('#d_alert_ctrl').html( '<i class="mdi mdi-bell mdi-lg">&nbsp;</i>Active' );
					}
					
				} ); // api.post
				
			} // user clicked set
		} ); // app.confirm
	},
	
	formatHostname: function(hostname) {
		// format hostname for display
		return hostname.replace( this.hostnameStrip, '' );
	},
	
	doUserLogin: function(resp) {
		// user login, called from login page, or session recover
		// overriding this from base.js, so we can pass the session ID to the websocket
		delete resp.code;
		
		for (var key in resp) {
			this[key] = resp[key];
		}
		
		this.setPref('username', resp.username);
		this.setPref('session_id', resp.session_id);
		
		this.updateHeaderInfo();
		
		// show admin tab if user is worthy
		if (this.isAdmin()) $('#tab_Admin').show();
		else $('#tab_Admin').hide();
	},
	
	doUserLogout: function(bad_cookie) {
		// log user out and redirect to login screen
		var self = this;
		
		if (!bad_cookie) {
			// user explicitly logging out
			this.showProgress(1.0, "Logging out...");
			this.setPref('username', '');
		}
		
		this.api.post( 'user/logout', {
			session_id: this.getPref('session_id')
		}, 
		function(resp, tx) {
			delete self.user;
			delete self.username;
			delete self.user_info;
			
			self.setPref('session_id', '');
			
			$('#d_header_user_container').html( '' );
			
			if (app.config.external_users) {
				// external user api
				Debug.trace("User session cookie was deleted, querying external user API");
				setTimeout( function() {
					if (bad_cookie) app.doExternalLogin(); 
					else app.doExternalLogout(); 
				}, 250 );
			}
			else {
				Debug.trace("User session cookie was deleted, redirecting to login page");
				self.hideProgress();
				Nav.go('Login');
			}
			
			setTimeout( function() {
				if (!app.config.external_users) {
					if (bad_cookie) self.showMessage('error', "Your session has expired.  Please log in again.");
					else self.showMessage('success', "You were logged out successfully.");
				}
				
				delete self.plugins;
				delete self.epoch;
				
			}, 150 );
			
			$('#tab_Admin').hide();
		} );
	},
	
	doExternalLogin: function() {
		// login using external user management system
		// Force API to hit current page hostname vs. master server, so login redirect URL reflects it
		app.api.post( '/api/user/external_login', { cookie: document.cookie }, function(resp) {
			if (resp.user) {
				Debug.trace("User Session Resume: " + resp.username + ": " + resp.session_id);
				app.hideProgress();
				app.doUserLogin( resp );
				Nav.refresh();
			}
			else if (resp.location) {
				Debug.trace("External User API requires redirect");
				app.showProgress(1.0, "Logging in...");
				setTimeout( function() { window.location = resp.location; }, 250 );
			}
			else app.doError(resp.description || "Unknown login error.");
		} );
	},
	
	doExternalLogout: function() {
		// redirect to external user management system for logout
		var url = app.config.external_user_api;
		url += (url.match(/\?/) ? '&' : '?') + 'logout=1';
		
		Debug.trace("External User API requires redirect");
		app.showProgress(1.0, "Logging out...");
		setTimeout( function() { window.location = url; }, 250 );
	},
	
	get_password_toggle_html: function() {
		// get html for a password toggle control
		return '<span class="link password_toggle" onMouseUp="app.toggle_password_field(this)">Hide</span>';
	},
	
	toggle_password_field: function(span) {
		// toggle password field visible / masked
		var $span = $(span);
		var $field = $span.prev();
		if ($field.attr('type') == 'password') {
			$field.attr('type', 'text');
			$span.html( 'Hide' );
		}
		else {
			$field.attr('type', 'password');
			$span.html( 'Show' );
		}
	},
	
	tick: function() {
		// fired every second from web worker
		var dargs = get_date_args(time_now());
		
		// pages may define a "tick" method
		if (app.page_manager && app.page_manager.current_page_id) {
			var page = app.page_manager.find(app.page_manager.current_page_id);
			if (page && page.tick) page.tick(dargs);
		}
		
		// allow page to listen for minute events
		if (dargs.sec == 0) {
			if (app.page_manager && app.page_manager.current_page_id) {
				var page = app.page_manager.find(app.page_manager.current_page_id);
				if (page && page.onMinute) page.onMinute(dargs);
			}
		}
		
		// allow page to listen for 30s events
		if (dargs.sec == 30) {
			if (app.page_manager && app.page_manager.current_page_id) {
				var page = app.page_manager.find(app.page_manager.current_page_id);
				if (page && page.onSecond30) page.onSecond30(dargs);
			}
		}
	},
	
	findMonitorsFromGroup: function(group) {
		// find all monitors that match group
		// but only if enabled for display
		if (typeof(group) == 'string') group = find_object( config.groups, { id: group } );
		if (!group) return [];
		var monitor_defs = [];
		
		for (var idx = 0, len = config.monitors.length; idx < len; idx++) {
			var monitor_def = config.monitors[idx];
			if (monitor_def.display && group.id.match(monitor_def.group_match)) monitor_defs.push(monitor_def);
		}
		
		// sort by sort_order
		return monitor_defs.sort( function(a, b) {
			return (a.sort_order < b.sort_order) ? -1 : 1;
		} );
	},
	
	findGroupFromHostData: function(metadata) {
		// find group by host metadata (host may define its own group) or by matching hostname
		if (metadata.group) return find_object( config.groups, { id: metadata.group } );
		return this.findGroupFromHostname( metadata.hostname );
	},
	
	findGroupFromHostname: function(hostname) {
		// find group by matching hostname
		for (var idx = 0, len = config.groups.length; idx < len; idx++) {
			var group_def = config.groups[idx];
			if (hostname.match(group_def.hostname_match)) return group_def;
		}
		return false;
	},
	
	customConfirm: function(title, html, ok_btn_label, callback) {
		// show simple OK / Cancel dialog with custom text
		// fires callback with true (OK) or false (Cancel)
		// the only difference between customConfirm and base confirm is this one allows for wider-than-450px dialogs
		if (!ok_btn_label) ok_btn_label = "OK";
		this.confirm_callback = callback;
		
		var inner_html = "";
		inner_html += '<div class="custom_confirm_container">'+html+'</div>';
		
		var buttons_html = "";
		buttons_html += '<center><table><tr>';
			buttons_html += '<td><div class="button" style="width:100px; font-weight:normal;" onMouseUp="app.confirm_click(false)">Cancel</div></td>';
			buttons_html += '<td width="60">&nbsp;</td>';
			buttons_html += '<td><div class="button" style="width:100px;" onMouseUp="app.confirm_click(true)">'+ok_btn_label+'</div></td>';
		buttons_html += '</tr></table></center>';
		
		this.showDialog( title, inner_html, buttons_html );
		
		// special mode for key capture
		Dialog.active = 'confirmation';
	},
	
	onFilterKeyUp: function() {
		// called for each keyup in graph filter text input (debounced to 50ms)
		if (app.page_manager && app.page_manager.current_page_id) {
			var page = app.page_manager.find(app.page_manager.current_page_id);
			if (page && page.onFilterKeyUp) page.onFilterKeyUp();
		}
	},
	
	onScrollDebounce: function() {
		// called every 50ms while scrolling
		if (app.page_manager && app.page_manager.current_page_id) {
			var page = app.page_manager.find(app.page_manager.current_page_id);
			if (page && page.onScrollDebounce) page.onScrollDebounce();
		}
	},
	
	onFocus: function() {
		// window received focus
		if (app.page_manager && app.page_manager.current_page_id) {
			var page = app.page_manager.find(app.page_manager.current_page_id);
			if (page && page.onFocus) page.onFocus();
		}
	},
	
	onThemeChange: function(theme) {
		// called when user changes theme (and on init)
		if (app.page_manager && app.page_manager.current_page_id) {
			var page = app.page_manager.find(app.page_manager.current_page_id);
			if (page && page.onThemeChange) page.onThemeChange(theme);
		}
	}
	
}); // app

window.Debug = {
	
	enabled: false,
	categories: { all: 1 },
	backlog: [],
	
	colors: ["#001F3F", "#0074D9", "#7FDBFF", "#39CCCC", "#3D9970", "#2ECC40", "#01FF70", "#FFDC00", "#FF851B", "#FF4136", "#F012BE", "#B10DC9", "#85144B"],
	nextColorIdx: 0,
	catColors: {},
	
	enable: function(cats) {
		// enable debug logging and flush backlog if applicable
		if (cats) this.categories = cats;
		this.enabled = true;
		this._dump();
	},
	
	disable: function() {
		// disable debug logging, but keep backlog
		this.enabled = false;
	},
	
	trace: function(cat, msg, data) {
		// trace one line to console, or store in backlog
		// allow msg, cat + msg, msg + data, or cat + msg + data
		if (arguments.length == 1) {
			msg = cat; 
			cat = 'debug'; 
		}
		else if ((arguments.length == 2) && (typeof(arguments[arguments.length - 1]) == 'object')) {
			data = msg;
			msg = cat;
			cat = 'debug';
		}
		
		var now = new Date();
		var timestamp = '' + 
			this._zeroPad( now.getHours(), 2 ) + ':' + 
			this._zeroPad( now.getMinutes(), 2 ) + ':' + 
			this._zeroPad( now.getSeconds(), 2 ) + '.' + 
			this._zeroPad( now.getMilliseconds(), 3 );
		
		if (data && (typeof(data) == 'object')) data = JSON.stringify(data);
		if (!data) data = false;
		
		if (this.enabled) {
			if ((this.categories.all || this.categories[cat]) && (this.categories[cat] !== false)) {
				this._print(timestamp, cat, msg, data);
			}
		}
		else {
			this.backlog.push([ timestamp, cat, msg, data ]);
			if (this.backlog.length > 1000) this.backlog.shift();
		}
	},
	
	_dump: function() {
		// dump backlog to console
		for (var idx = 0, len = this.backlog.length; idx < len; idx++) {
			this._print.apply( this, this.backlog[idx] );
		}
		this.backlog = [];
	},
	
	_print: function(timestamp, cat, msg, data) {
		// format and print one message to the console
		var color = this.catColors[cat] || '';
		if (!color) {
			color = this.catColors[cat] = this.colors[this.nextColorIdx];
			this.nextColorIdx = (this.nextColorIdx + 1) % this.colors.length;
		}
		
		console.log( timestamp + ' %c[' + cat + ']%c ' + msg, 'color:' + color + '; font-weight:bold', 'color:inherit; font-weight:normal' );
		if (data) console.log(data);
	},
	
	_zeroPad: function(value, len) {
		// Pad a number with zeroes to achieve a desired total length (max 10)
		return ('0000000000' + value).slice(0 - len);
	}
};

function short_float_str(num) {
	// force a float (add suffix if int)
	num = '' + short_float(num);
	if (num.match(/^\-?\d+$/)) num += ".0";
	return num;
};

// Debounce Function Generator
// Fires once immediately, then never again until freq ms
function debounce(func, freq) {
	var timeout = null;
	var requestFire = false;
	
	return function() {
		var context = this, args = arguments;
		var later = function() {
			timeout = null;
			if (requestFire) {
				func.apply(context, args);
				requestFire = false;
			}
		};
		if (!timeout) {
			func.apply(context, args);
			timeout = setTimeout(later, freq);
			requestFire = false;
		}
		else {
			requestFire = true;
		}
	};
};

// Copy text to clipboard
// borrowed from: https://github.com/feross/clipboard-copy (MIT License)
function copyToClipboard(text) {
	// Put the text to copy into a <span>
	var span = document.createElement('span');
	span.textContent = text;
	
	// Preserve consecutive spaces and newlines
	span.style.whiteSpace = 'pre';
	
	// Add the <span> to the page
	document.body.appendChild(span);
	
	// Make a selection object representing the range of text selected by the user
	var selection = window.getSelection();
	var range = window.document.createRange();
	selection.removeAllRanges();
	range.selectNode(span);
	selection.addRange(range);
	
	// Copy text to the clipboard
	var success = false;
	try {
		success = window.document.execCommand('copy');
	} 
	catch (err) {
		console.log('error', err);
	}
	
	// Cleanup
	selection.removeAllRanges();
	window.document.body.removeChild(span);
};

// ----------------------------------------------
// https://github.com/teamdf/jquery-visible
(function($){
	/**
	 * Copyright 2012, Digital Fusion
	 * Licensed under the MIT license.
	 * http://teamdf.com/jquery-plugins/license/
	 *
	 * @author Sam Sehnert
	 * @desc A small plugin that checks whether elements are within
	 *	   the user visible viewport of a web browser.
	 *	   only accounts for vertical position, not horizontal.
	 */
	var $w = $(window);
	$.fn.visible = function(partial,hidden,direction){

		if (this.length < 1)
			return;

		var $t		= this.length > 1 ? this.eq(0) : this,
			t		 = $t.get(0),
			vpWidth   = $w.width(),
			vpHeight  = $w.height(),
			direction = (direction) ? direction : 'both',
			clientSize = hidden === true ? t.offsetWidth * t.offsetHeight : true;

		if (typeof t.getBoundingClientRect === 'function'){

			// Use this native browser method, if available.
			var rec = t.getBoundingClientRect(),
				tViz = rec.top	>= 0 && rec.top	<  vpHeight,
				bViz = rec.bottom >  0 && rec.bottom <= vpHeight,
				lViz = rec.left   >= 0 && rec.left   <  vpWidth,
				rViz = rec.right  >  0 && rec.right  <= vpWidth,
				vVisible   = partial ? tViz || bViz : tViz && bViz,
				hVisible   = partial ? lViz || rViz : lViz && rViz;

			if(direction === 'both')
				return clientSize && vVisible && hVisible;
			else if(direction === 'vertical')
				return clientSize && vVisible;
			else if(direction === 'horizontal')
				return clientSize && hVisible;
		} else {

			var viewTop		 = $w.scrollTop(),
				viewBottom	  = viewTop + vpHeight,
				viewLeft		= $w.scrollLeft(),
				viewRight	   = viewLeft + vpWidth,
				offset		  = $t.offset(),
				_top			= offset.top,
				_bottom		 = _top + $t.height(),
				_left		   = offset.left,
				_right		  = _left + $t.width(),
				compareTop	  = partial === true ? _bottom : _top,
				compareBottom   = partial === true ? _top : _bottom,
				compareLeft	 = partial === true ? _right : _left,
				compareRight	= partial === true ? _left : _right;

			if(direction === 'both')
				return !!clientSize && ((compareBottom <= viewBottom) && (compareTop >= viewTop)) && ((compareRight <= viewRight) && (compareLeft >= viewLeft));
			else if(direction === 'vertical')
				return !!clientSize && ((compareBottom <= viewBottom) && (compareTop >= viewTop));
			else if(direction === 'horizontal')
				return !!clientSize && ((compareRight <= viewRight) && (compareLeft >= viewLeft));
		}
	};

})(jQuery);

// onFontReady v1.1.0 (MIT License)
// https://github.com/dwighthouse/onfontready/blob/master/LICENSE
window.onfontready=function(e,t,i,n,o){i=i||0,i.timeoutAfter&&setTimeout(function(){n&&(document.body.removeChild(n),n=0,i.onTimeout&&i.onTimeout())},i.timeoutAfter),o=function(){n&&n.firstChild.clientWidth==n.lastChild.clientWidth&&(document.body.removeChild(n),n=0,t())},o(document.body.appendChild(n=document.createElement("div")).innerHTML='<div style="position:fixed;white-space:pre;bottom:999%;right:999%;font:999px '+(i.generic?"":"'")+e+(i.generic?"":"'")+',serif">'+(i.sampleText||" ")+'</div><div style="position:fixed;white-space:pre;bottom:999%;right:999%;font:999px '+(i.generic?"":"'")+e+(i.generic?"":"'")+',monospace">'+(i.sampleText||" ")+"</div>"),n&&(n.firstChild.appendChild(e=document.createElement("iframe")).style.width="999%",e.contentWindow.onresize=o,n.lastChild.appendChild(e=document.createElement("iframe")).style.width="999%",e.contentWindow.onresize=o,e=setTimeout(o))};
window.onfontsready=function(e,t,n,o,i){for(n=n||0,o=i=0;o<e.length;o++)window.onfontready(e[o],function(){++i>=e.length&&t()},{timeoutAfter:n.timeoutAfter,sampleText:n.sampleText instanceof Array?n.sampleText[o]:n.sampleText,generic:n.generic instanceof Array?n.generic[o]:n.generic});n.timeoutAfter&&n.onTimeout&&setTimeout(function(){i<e.length&&n.onTimeout(i=NaN)},n.timeoutAfter)};

Class.subclass( Page, "Page.Base", {	
	
	// milliseconds between dequeuing items
	queueDelay: 10,
	
	// graphColors: ["#7cb5ec", "#535358", "#90ed7d", "#f7a35c", "#8085e9", "#f15c80", "#e4d354", "#8085e8", "#8d4653", "#91e8e1"],
	graphColors: [ "#008FFB", "#00E396", "#FEB019", "#FF4560", "#775DD0", "#3F51B5", "#4CAF50", "#546E7A", "#D4526E", "#A5978B", "#C7F464", "#81D4FA", "#2B908F", "#F9A3A4", "#90EE7E", "#FA4443", "#449DD1", "#F86624", "#69D2E7", "#EA3546", "#662E9B", "#C5D86D", "#D7263D", "#1B998B", "#2E294E", "#F46036", "#E2C044", "#662E9B", "#F86624", "#F9C80E", "#EA3546", "#43BCCD", "#5C4742", "#A5978B", "#8D5B4C", "#5A2A27", "#C4BBAF", "#A300D6", "#7D02EB", "#5653FE", "#2983FF", "#00B1F2", "#03A9F4", "#33B2DF", "#4ECDC4", "#13D8AA", "#FD6A6A", "#F9CE1D", "#FF9800" ],
	
	graphSizeSettings: {
		full: {
			height: 400,
			line_thickness: 3,
			xaxis_ticks: 6,
			title_font_size: '16px'
		},
		half: {
			height: 300,
			line_thickness: 2,
			xaxis_ticks: 6,
			title_font_size: '15px'
		},
		third: {
			height: 200,
			line_thickness: 2,
			xaxis_ticks: 4,
			title_font_size: '14px'
		}
	},
	
	requireLogin: function(args) {
		// user must be logged into to continue
		var self = this;
		
		if (!app.user) {
			// require login
			app.navAfterLogin = this.ID;
			if (args && num_keys(args)) app.navAfterLogin += compose_query_string(args);
			
			this.div.hide();
			
			var session_id = app.getPref('session_id') || '';
			if (session_id) {
				Debug.trace("User has cookie, recovering session: " + session_id);
				
				app.api.post( 'user/resume_session', {
					session_id: session_id
				}, 
				function(resp) {
					if (resp.user) {
						Debug.trace("User Session Resume: " + resp.username + ": " + resp.session_id);
						app.hideProgress();
						app.doUserLogin( resp );
						Nav.refresh();
					}
					else {
						Debug.trace("User cookie is invalid, redirecting to login page");
						// Nav.go('Login');
						self.setPref('session_id', '');
						self.requireLogin(args);
					}
				} );
			}
			else if (app.config.external_users) {
				Debug.trace("User is not logged in, querying external user API");
				app.doExternalLogin();
			}
			else {
				Debug.trace("User is not logged in, redirecting to login page (will return to " + this.ID + ")");
				setTimeout( function() { Nav.go('Login'); }, 1 );
			}
			return false;
		}
		return true;
	},
	
	isAdmin: function() {
		// return true if user is logged in and admin, false otherwise
		// Note: This is used for UI decoration ONLY -- all privileges are checked on the server
		return( app.user && app.user.privileges && app.user.privileges.admin );
	},
		
	getNiceGroupList: function(group_match, link, width) {
		// convert regexp into comma-separated group title list
		if (group_match == '.+') return '(All)';
		if (group_match == '(?!)') return '(None)';
		
		var titles = [];
		group_match.split(/\W+/).forEach( function(group_id) {
			if (group_id.match(/^\w+$/)) {
				var group = find_object( config.groups, { id: group_id } );
				if (!group) group = { id: group_id, title: group_id };
				var title = '';
				if (link) title += '<a href="#Admin?sub=edit_group&id=' + group.id + '">';
				title += '<i class="mdi mdi-server-network">&nbsp;</i>' + group.title;
				if (link) title += '</a>';
				titles.push( title );
			}
		});
		
		var html = '<div class="ellip" style="max-width:' + width + 'px;">';
		html += titles.join(', ');
		html += '</div>';
		
		return html;
	},
	
	getNiceGroup: function(item, link, width) {
		// get formatted group with icon, plus optional link
		if (!width) width = 500;
		if (!item) return '(None)';
		
		var html = '<div class="ellip" style="max-width:' + width + 'px;">';
		var icon = '<i class="mdi mdi-server-network">&nbsp;</i>';
		if (link) {
			if (link === true) link = '#Admin?sub=edit_group&id=' + item.id;
			html += '<a href="' + link + '" style="text-decoration:none">';
			html += icon + '<span style="text-decoration:underline">' + item.title + '</span></a>';
		}
		else {
			html += icon + item.title;
		}
		html += '</div>';
		
		return html;
	},
	
	getNiceMonitor: function(item, link, width) {
		// get formatted monitor with icon, plus optional link
		if (!width) width = 500;
		if (!item) return '(None)';
		
		var html = '<div class="ellip" style="max-width:' + width + 'px;">';
		var icon = '<i class="mdi mdi-chart-line">&nbsp;</i>';
		if (link) {
			html += '<a href="#Admin?sub=edit_monitor&id=' + item.id + '" style="text-decoration:none">';
			html += icon + '<span style="text-decoration:underline">' + item.title + '</span></a>';
		}
		else {
			html += icon + item.title;
		}
		html += '</div>';
		
		return html;
	},
	
	getNiceAlert: function(item, link, width) {
		// get formatted alert with icon, plus optional link
		if (!width) width = 500;
		if (!item) return '(None)';
		
		var html = '<div class="ellip" style="max-width:' + width + 'px;">';
		var icon = '<i class="mdi ' + (item.enabled ? 'mdi-bell' : 'mdi-bell-off') + '">&nbsp;</i>';
		if (link) {
			html += '<a href="#Admin?sub=edit_alert&id=' + item.id + '" style="text-decoration:none">';
			html += icon + '<span style="text-decoration:underline">' + item.title + '</span></a>';
		}
		else {
			html += icon + item.title;
		}
		html += '</div>';
		
		return html;
	},
	
	getNiceCommand: function(item, link, width) {
		// get formatted command with icon, plus optional link
		if (!width) width = 500;
		if (!item) return '(None)';
		
		var html = '<div class="ellip" style="max-width:' + width + 'px;">';
		var icon = '<i class="mdi mdi-console">&nbsp;</i>';
		if (link) {
			html += '<a href="#Admin?sub=edit_command&id=' + item.id + '" style="text-decoration:none">';
			html += icon + '<span style="text-decoration:underline">' + item.title + '</span></a>';
		}
		else {
			html += icon + item.title;
		}
		html += '</div>';
		
		return html;
	},
	
	getNiceAPIKey: function(item, link, width) {
		// get formatted api key with icon, plus optional link
		if (!item) return 'n/a';
		if (!width) width = 500;
		var key = item.api_key || item.key;
		var title = item.api_title || item.title;
		
		var html = '<div class="ellip" style="max-width:'+width+'px;">';
		var icon = '<i class="mdi mdi-key-variant">&nbsp;</i>';
		if (link && key) {
			html += '<a href="#Admin?sub=edit_api_key&id=' + item.id + '" style="text-decoration:none">';
			html += icon + '<span style="text-decoration:underline">' + title + '</span></a>';
		}
		else {
			html += icon + title;
		}
		html += '</div>';
		
		return html;
	},
	
	getNiceUsername: function(user, link, width) {
		// get formatted username with icon, plus optional link
		if (!user) return 'n/a';
		if ((typeof(user) == 'object') && (user.key || user.api_title)) {
			return this.getNiceAPIKey(user, link, width);
		}
		if (!width) width = 500;
		var username = user.username ? user.username : user;
		if (!username || (typeof(username) != 'string')) return 'n/a';
		
		var html = '<div class="ellip" style="max-width:'+width+'px;">';
		var icon = '<i class="fa fa-user">&nbsp;</i>';
		
		if (link) {
			html += '<a href="#Admin?sub=edit_user&username=' + username + '" style="text-decoration:none">';
			html += icon + '<span style="text-decoration:underline">' + username + '</span></a>';
		}
		else {
			html += icon + username;
		}
		html += '</div>';
		
		return html;
	},
	
	getNiceHostname: function(hostname, link, width) {
		// get formatted hostname with icon, plus optional link
		if (!width) width = 500;
		if (!hostname) return '(None)';
		
		var query = { hostname: hostname };
		if (this.args && this.args.sys) query.sys = this.args.sys;
		if (this.args && this.args.date) query.date = this.args.date;
		if (this.args && ('offset' in this.args)) query.offset = this.args.offset;
		if (this.args && this.args.length) query.length = this.args.length;
		
		var html = '<div class="ellip" style="max-width:' + width + 'px;">';
		var icon = '<i class="mdi mdi-desktop-tower">&nbsp;</i>';
		if (link) {
			html += '<a href="#Server' + compose_query_string(query) + '" style="text-decoration:none">';
			html += icon + '<span style="text-decoration:underline">' + this.formatHostname(hostname) + '</span></a>';
		}
		else {
			html += icon + this.formatHostname(hostname);
		}
		html += '</div>';
		
		return html;
	},
	
	setGroupVisible: function(group, visible) {
		// set web groups of form fields visible or invisible, 
		// according to master checkbox for each section
		var selector = 'tr.' + group + 'group';
		if (visible) {
			if ($(selector).hasClass('collapse')) {
				$(selector).hide().removeClass('collapse');
			}
			$(selector).show(250);
		}
		else $(selector).hide(250);
		
		return this; // for chaining
	},
	
	checkUserExists: function(pre) {
		// check if user exists, update UI checkbox
		// called after field changes
		var username = trim($('#fe_'+pre+'_username').val().toLowerCase());
		var $elem = $('#d_'+pre+'_valid');
		
		if (username.match(/^[\w\-\.]+$/)) {
			// check with server
			// $elem.css('color','#444').html('<span class="fa fa-spinner fa-spin fa-lg">&nbsp;</span>');
			app.api.get('app/check_user_exists', { username: username }, function(resp) {
				if (resp.user_exists) {
					// username taken
					$elem.css('color','red').html('<span class="fa fa-exclamation-triangle fa-lg">&nbsp;</span>Username Taken');
				}
				else {
					// username is valid and available!
					$elem.css('color','green').html('<span class="fa fa-check-circle fa-lg">&nbsp;</span>Available');
				}
			} );
		}
		else if (username.length) {
			// bad username
			$elem.css('color','red').html('<span class="fa fa-exclamation-triangle fa-lg">&nbsp;</span>Bad Username');
		}
		else {
			// empty
			$elem.html('');
		}
	},
	
	check_add_remove_me: function($elem) {
		// check if user's e-mail is contained in text field or not
		var value = $elem.val().toLowerCase();
		var email = app.user.email.toLowerCase();
		var regexp = new RegExp( "\\b" + escape_regexp(email) + "\\b" );
		return !!value.match(regexp);
	},
	
	update_add_remove_me: function($elems) {
		// update add/remove me text based on if user's e-mail is contained in text field
		var self = this;
				
		$elems.each( function() {
			var $elem = $(this);
			var $span = $elem.next();
						
			if (self.check_add_remove_me($elem)) $span.html( '&raquo; Remove me' );
			else $span.html( '&laquo; Add me' );
		} );
	},
	
	add_remove_me: function($elem) {
		// toggle user's e-mail in/out of text field
		var value = trim( $elem.val().replace(/\,\s*\,/g, ',').replace(/^\s*\,\s*/, '').replace(/\s*\,\s*$/, '') );
		
		if (this.check_add_remove_me($elem)) {
			// remove e-mail
			var email = app.user.email.toLowerCase();
			var regexp = new RegExp( "\\b" + escape_regexp(email) + "\\b", "i" );
			value = value.replace( regexp, '' ).replace(/\,\s*\,/g, ',').replace(/^\s*\,\s*/, '').replace(/\s*\,\s*$/, '');
			$elem.val( trim(value) );
		}
		else {
			// add email
			if (value) value += ', ';
			$elem.val( value + app.user.email );
		}
		
		this.update_add_remove_me($elem);
	},
	
	get_custom_combo_unit_box: function(id, value, items, class_name) {
		// get HTML for custom combo text/menu, where menu defines units of measurement
		// items should be array for use in render_menu_options(), with an increasing numerical value
		if (!class_name) class_name = 'std_combo_unit_table';
		var units = 0;
		var value = parseInt( value || 0 );
		
		for (var idx = items.length - 1; idx >= 0; idx--) {
			var max = items[idx][0];
			if ((value >= max) && (value % max == 0)) {
				units = max;
				value = Math.floor( value / units );
				idx = -1;
			}
		}
		if (!units) {
			// no exact match, so default to first unit in list
			units = items[0][0];
			value = Math.floor( value / units );
		}
		
		return (
			'<table cellspacing="0" cellpadding="0" class="'+class_name+'"><tr>' + 
				'<td style="padding:0"><input type="text" id="'+id+'" style="width:30px;" value="'+value+'"/></td>' + 
				'<td style="padding:0"><select id="'+id+'_units">' + render_menu_options(items, units) + '</select></td>' + 
			'</tr></table>' 
		);
	},
	
	get_relative_time_combo_box: function(id, value, class_name, inc_seconds) {
		// get HTML for combo textfield/menu for a relative time based input
		// provides Minutes, Hours and Days units
		var unit_items = [[60,'Minutes'], [3600,'Hours'], [86400,'Days']];
		if (inc_seconds) unit_items.unshift( [1,'Seconds'] );
		
		return this.get_custom_combo_unit_box( id, value, unit_items, class_name );
	},
	
	get_relative_size_combo_box: function(id, value, class_name) {
		// get HTML for combo textfield/menu for a relative size based input
		// provides MB, GB and TB units
		var TB = 1024 * 1024 * 1024 * 1024;
		var GB = 1024 * 1024 * 1024;
		var MB = 1024 * 1024;
		
		return this.get_custom_combo_unit_box( id, value, [[MB,'MB'], [GB,'GB'], [TB,'TB']], class_name );
	},
	
	expand_fieldset: function($span) {
		// expand neighboring fieldset, and hide click control
		var $div = $span.parent();
		var $fieldset = $div.next();
		$fieldset.show( 350 );
		$div.hide( 350 );
	},
	
	collapse_fieldset: function($legend) {
		// collapse fieldset, and show click control again
		var $fieldset = $legend.parent();
		var $div = $fieldset.prev();
		$fieldset.hide( 350 );
		$div.show( 350 );
	},
	
	doInlineError(title, msg) {
		// show inline error on page
		this.onDeactivate(); // kill all graphs
		var html = '';
		html += '<fieldset class="inline_error">';
		html += '<div class="inline_error_title">' + title + '</div>';
		html += '<div class="inline_error_msg">' + msg + '</div>';
		html += '</fieldset>';
		this.div.removeClass('loading').html(html);
		$('#d_ctrl_range > .info_value').html( 'n/a' );
	},
	
	formatHostname: function(hostname) {
		// format hostname for display
		return app.formatHostname(hostname);
	},
	
	showControls: function(enabled) {
		// show or hide main date/size controls
		var self = this;
		var args = this.args;
		
		if (!enabled) {
			$('#d_controls').hide();
			return;
		}
		$('#d_controls').show();
		
		// possibly show server dropdown
		// (update contents as it can change over time)
		if (args.hostname) {
			if (!app.recent_hostnames[args.hostname]) app.recent_hostnames[args.hostname] = 1;
			$('#d_ctrl_server').show();
			$('#fe_ctrl_server').empty().append( app.getRecentServerMenuOptionsHTML() ).val( args.hostname );
		}
		else $('#d_ctrl_server').hide();
		
		// possibly show group dropdown
		if (args.group) {
			$('#d_ctrl_group').show();
			$('#fe_ctrl_group').val( args.group );
		}
		else $('#d_ctrl_group').hide();
		
		// populate scale menu
		var scale_html = '';
		scale_html += '<optgroup label="Live">' + 
				'<option value="live_60">Last Hour</option>' + 
				'<option value="live_180">Last 3 Hours</option>' + 
				'<option value="live_360">Last 6 Hours</option>' + 
				'<option value="live_720">Last 12 Hours</option>' + 
			'</optgroup>';
		if (args.hostname || args.group) {
			// group and server view have historical options
			scale_html += '<option value="" disabled></option>';
			scale_html += '<optgroup label="Historical">' + 
					'<option value="hist_hourly">Hourly</option>' + 
					'<option value="hist_daily">Daily</option>' + 
					'<option value="hist_monthly">Monthly</option>' + 
					'<option value="hist_yearly">Yearly</option>' + 
				'</optgroup>';
		}
		$('#fe_ctrl_mode').empty().append( scale_html );
		
		// determine scale mode
		// fe_ctrl_mode: live_60, live_180, live_360, live_720, hist_hourly, hist_daily, hist_monthly, hist_yearly
		if (args.date) {
			// historical
			$('#fe_ctrl_mode').val( 'hist_' + args.sys );
		}
		else {
			// some kind of live
			$('#fe_ctrl_mode').val( 'live_' + args.length );
		}
		
		// fe_ctrl_mode, d_ctrl_date, fe_ctrl_year, fe_ctrl_month, fe_ctrl_day, fe_ctrl_hour
		// btn_nav_left, btn_nav_right, btn_csi_third, btn_csi_half, btn_csi_full
		
		if (args.date) {
			// historical view
			$('#d_ctrl_date').show();
			
			if (args.date.match(/^(\d{4})\D+(\d{2})\D+(\d{2})\D+(\d{2})$/)) {
				// hourly
				var yyyy = RegExp.$1;
				var mm = RegExp.$2;
				var dd = RegExp.$3;
				var hh = RegExp.$4;
				$('#fe_ctrl_year').show().val( yyyy );
				$('#fe_ctrl_month').show().val( mm );
				$('#fe_ctrl_day').show().val( dd );
				$('#fe_ctrl_hour').show().val( hh );
			}
			else if (args.date.match(/^(\d{4})\D+(\d{2})\D+(\d{2})$/)) {
				// daily
				var yyyy = RegExp.$1;
				var mm = RegExp.$2;
				var dd = RegExp.$3;
				$('#fe_ctrl_year').show().val( yyyy );
				$('#fe_ctrl_month').show().val( mm );
				$('#fe_ctrl_day').show().val( dd );
				$('#fe_ctrl_hour').hide().val( "00" );
			}
			else if (args.date.match(/^(\d{4})\D+(\d{2})$/)) {
				// monthly
				var yyyy = RegExp.$1;
				var mm = RegExp.$2;
				$('#fe_ctrl_year').show().val( yyyy );
				$('#fe_ctrl_month').show().val( mm );
				$('#fe_ctrl_day').hide().val( "01" );
				$('#fe_ctrl_hour').hide().val( "00" );
			}
			else if (args.date.match(/^(\d{4})$/)) {
				// yearly
				var yyyy = RegExp.$1;
				$('#fe_ctrl_year').show().val( yyyy );
				$('#fe_ctrl_month').hide().val( "01" );
				$('#fe_ctrl_day').hide().val( "01" );
				$('#fe_ctrl_hour').hide().val( "00" );
			}
		}
		else {
			// live view
			$('#d_ctrl_date').hide();
			
			// set date to today in menus
			var dargs = get_date_args( time_now() );
			$('#fe_ctrl_year').show().val( dargs.yyyy );
			$('#fe_ctrl_month').show().val( dargs.mm );
			$('#fe_ctrl_day').show().val( dargs.dd );
			$('#fe_ctrl_hour').show().val( dargs.hh );
		}
		
		// graph size
		$('#btn_csi_third, #btn_csi_half, #btn_csi_full').removeClass('selected');
		
		if (args.hostname || args.group) {
			$('#btn_csi_' + app.getPref('graph_size')).addClass('selected');
		}
		else {
			$('#btn_csi_' + app.getPref('ov_graph_size')).addClass('selected');
		}
		
		if (this.isRealTime()) {
			// data range (will be filled in later)
			$('#d_ctrl_range').show().find('.info_value').html('');
			
			// auto-refresh checkbox
			$('#d_ctrl_opts').show();
			$('#fe_ctrl_auto_refresh').prop('checked', app.getPref('auto_refresh') == '1' );
			$('#fe_ctrl_annotations').prop('checked', app.getPref('annotations') == '1' );
		}
		else {
			$('#d_ctrl_range').hide();
			$('#d_ctrl_opts').hide();
		}
	},
	
	navToArgs: function() {
		// recompose args into #URI and nav to it
		delete this.args.cachebust;
		Nav.go( '#' + this.ID + compose_query_string(this.args) );
	},
	
	navReplaceArgs: function() {
		// recompose args into #URI and replace the current history state with it
		// (this does NOT fire a hashchange)
		delete this.args.cachebust;
		history.replaceState( {}, "", '#' + this.ID + compose_query_string(this.args) );
	},
	
	setControlMode: function(mode) {
		// set new control (zoom) mode
		if (!mode) mode = $('#fe_ctrl_mode').val();
		var args = this.args;
		
		if (mode.match(/live_(\d+)$/)) {
			// one of the live modes: live_60, live_180, live_360, live_720
			var new_len = parseInt( RegExp.$1 );
			delete args.date;
			if (args.hostname || args.group) args.sys = 'hourly';
			args.offset = 0 - new_len;
			args.length = new_len;
			this.navToArgs();
		}
		else if (mode.match(/hist_(\w+)$/)) {
			// one of the historical modes: hist_hourly, hist_daily, hist_monthly, hist_yearly
			var new_sys = RegExp.$1;
			args.sys = new_sys;
			delete args.offset;
			delete args.length;
			
			switch (new_sys) {
				case 'hourly':
					args.date = $('#fe_ctrl_year').val() + '/' + $('#fe_ctrl_month').val() + '/' + $('#fe_ctrl_day').val() + '/' + $('#fe_ctrl_hour').val();
				break;
				
				case 'daily':
					args.date = $('#fe_ctrl_year').val() + '/' + $('#fe_ctrl_month').val() + '/' + $('#fe_ctrl_day').val();
				break;
				
				case 'monthly':
					args.date = $('#fe_ctrl_year').val() + '/' + $('#fe_ctrl_month').val();
				break;
				
				case 'yearly':
					args.date = $('#fe_ctrl_year').val();
				break;
			}
			
			this.navToArgs();
		}
	},
	
	setChartSize: function(size) {
		// change chart size (via user click)
		var args = this.args;
		var pref_key = (args.hostname || args.group) ? 'graph_size' : 'ov_graph_size';
		app.setPref(pref_key, size);
		
		for (var mon_id in this.graphs) {
			var graph = this.graphs[ mon_id ];
			var settings = this.graphSettings[ mon_id ];
			$('#' + settings.canvas_id).empty().removeAttr('style');
		}
		
		// change chart size and redraw
		this.div.find('div.graphs')
			.removeClass('size_full size_half size_third')
			.addClass('size_' + size);
		
		for (var mon_id in this.graphs) {
			var graph = this.graphs[ mon_id ];
			var options = this.getGraphConfig(mon_id);
			graph.updateOptions( options, false, false );
			graph.render();
		}
		
		// update buttons
		$('#btn_csi_third, #btn_csi_half, #btn_csi_full').removeClass('selected');
		$('#btn_csi_' + size).addClass('selected');
	},
	
	toggleAutoRefresh: function() {
		// toggle auto-refresh user preference, read from checkbox
		if ($('#fe_ctrl_auto_refresh').is(':checked')) {
			app.setPref('auto_refresh', '1'); // always strings
			
			// trigger a focus refresh here (to catch things up)
			app.onFocus();
		}
		else {
			app.setPref('auto_refresh', '0'); // always strings
		}
	},
	
	toggleAnnotations: function() {
		// toggle annotations user preference, read from checkbox
		if ($('#fe_ctrl_annotations').is(':checked')) {
			app.setPref('annotations', '1'); // always strings
		}
		else {
			app.setPref('annotations', '0'); // always strings
		}
		
		// trigger a graph redraw
		this.onThemeChange();
	},
	
	displayDataRange: function(min_date, max_date) {
		// display current data range
		// (min and max should be epoch seconds)
		var html = '';
		
		if (min_date && max_date) {
			var min_dargs = get_date_args( min_date );
			html = format_date( min_dargs, '[mmmm] [mday], [hour12]:[mi] [AMPM]' );
			
			if (max_date > min_date) {
				var max_dargs = get_date_args( max_date );
				html += ' - ' + format_date( max_dargs, '[hour12]:[mi] [AMPM]' );
			}
		}
		else {
			html = 'n/a';
		}
		
		$('#d_ctrl_range > .info_value').html( html );
	},
	
	onFilterKeyUp: function() {
		// user has pressed a key in the filter text field (debounced to 50ms)
		// hide/show graphs as needed, trigger scroll redraw
		app.monitorFilter = $('#fe_ctrl_filter').val().trim().toLowerCase();
		this.applyMonitorFilter();
	},
	
	applyMonitorFilter: function() {
		// override in home / group / server
	},
	
	arraySpread: function(value, len) {
		// generate array with `num` elements all containing `value`
		// this is for a crazy ApexCharts quirk
		var arr = [];
		for (var idx = 0; idx < len; idx++) {
			arr.push( value );
		}
		return arr;
	},
	
	getGraphConfig: function(id) {
		// get complete graph config (sans data) given ID
		var self = this;
		var args = this.args;
		var settings = this.graphSettings[ id ];
		
		var theme = app.getPref('theme') || 'light';
		var pref_key = (args.hostname || args.group) ? 'graph_size' : 'ov_graph_size';
		var size_settings = this.graphSizeSettings[ app.getPref(pref_key) ];
		var line_thickness = size_settings.line_thickness;
		
		// setup our legend under the chart
		var legend_opts = {
			show: true,
			labels: {
				colors: [ '#888' ]
			}
		};
		
		// disable legend if there is only one layer
		if ((settings.num_layers == 1) && !settings.show_legend) legend_opts.show = false;
		else if (settings.num_layers > config.max_legend_size) legend_opts.show = false;
		
		// setup our timeline options
		var time_fmt = '[hour12]:[mi][ampm]';
		switch (args.sys) {
			case 'hourly':
				time_fmt = '[hour12]:[mi][ampm]';
			break;
			
			case 'daily':
				time_fmt = '[hour12][ampm]';
			break;
			
			case 'monthly':
		 		time_fmt = '[mmm] [mday]';
			break;
			
			case 'yearly':
				time_fmt = '[mmm]';
			break;
		} // switch sys
		
		// custom or default colors
		var colors = settings.color ? [settings.color] : this.graphColors;
		
		// generate graph via ApexCharts
		var options = {
			chart: {
				type: 'line',
				height: size_settings.height,
				fontFamily: '"Lato", "Helvetica", sans-serif',
				animations: {
					enabled: false
				},
				toolbar: {
					show: false,
					tools: {
						download: false,
						selection: false,
						zoom: false,
						zoomin: false,
						zoomout: false,
						pan: false,
						reset: false
					},
					autoSelected: 'zoom'
				}
			},
			colors: colors,
			title: {
				text: settings.title,
				align: 'center',
				margin: 0,
				offsetX: 0,
				offsetY: args.group ? 10 : 0,
				floating: false,
				style: {
					fontFamily: '"LatoBold", "Helvetica", sans-serif',
					// fontSize: '16px',
					fontSize: size_settings.title_font_size,
					color: '#888'
				}
			},
			dataLabels: {
				enabled: false
			},
			stroke: {
				show: true,
				curve: 'smooth',
				lineCap: 'butt',
				colors: undefined,
				width: line_thickness,
				dashArray: 0
			},
			markers: {
				size: 0,
				style: 'hollow'
			},
			xaxis: {
				type: 'datetime',
				tickAmount: size_settings.xaxis_ticks,
				labels: {
					formatter: function(value, timestamp, index) {
						// xaxis timestamp
						if (index == size_settings.xaxis_ticks) return '';
						return format_date( timestamp / 1000, time_fmt );
					},
					style: {
						colors: this.arraySpread( '#888', 10 )
					},
					// trim: true
				},
				tooltip: {
					enabled: false
				}
			},
			yaxis: {
				show: true,
				min: 0,
				forceNiceScale: true,
				labels: {
					formatter: function(value) {
						// format data value for both yaxis and tooltip here
						if (isNaN(value) || (value === null)) return 'n/a';
						if (value < 0) return '';
						return '' + self.formatDataValue(value, settings);
					},
					style: {
						color: '#888'
					}
				}
			},
			tooltip: {
				x: {
					enabled: true,
					shared: true,
					formatter: function(timestamp) {
						// tooltip timestamp
						return format_date( timestamp / 1000, "[yyyy]/[mm]/[dd] [hour12]:[mi][ampm]" );
					}
				},
				theme: theme
			},
			grid: {
				show: true,
				borderColor: 'rgba(128, 128, 128, 0.25)',
				xaxis: {
					lines: {
						show: true,
						
					}
				},
				yaxis: {
					lines: {
						show: true,
						
					}
				}
			},
			legend: legend_opts
		}; // options
		
		if ((settings.num_layers == 1) && !settings.no_fill) {
			// single layer, go area with alpha fill
			options.chart.type = 'area';
			options.fill = {
				type: 'solid',
				opacity: 0.5
			};
		}
		else {
			options.fill = {
				opacity: 1.0
			};
		}
		
		// allow config overrides
		if (config.graph_overrides && config.graph_overrides.all_sizes) {
			for (var path in config.graph_overrides.all_sizes) {
				setPath( options, path, config.graph_overrides.all_sizes[path] );
			}
		}
		
		var size_key = app.getPref(pref_key);
		if (config.graph_overrides && config.graph_overrides[size_key]) {
			for (var path in config.graph_overrides[size_key]) {
				setPath( options, path, config.graph_overrides[size_key][path] );
			}
		}
		
		return options;
	},
	
	createGraph: function(settings) {
		// generate graph given settings and page layout
		var self = this;
		var args = this.args;
		
		// save settings based on ID
		if (!this.graphSettings) this.graphSettings = {};
		this.graphSettings[ settings.id ] = settings;
		
		var datasets = settings.datasets || null;
		if (!datasets) {
			datasets = [];
			
			for (var idx = 0, len = settings.num_layers; idx < len; idx++) {
				var dataset = {
					name: "",
					data: []
				};
				
				// labels may be specified as array
				if (settings.labels) dataset.name = settings.labels[idx];
				
				datasets.push( dataset );
			} // foreach dataset
		} // create empty datasets
		
		var options = this.getGraphConfig(settings.id);
		options.series = datasets;
		
		var chart = new ApexCharts(
			$('#' + settings.canvas_id).get(0),
			options
		);
		
		chart.render();
		return chart;
	},
	
	crushData: function(data) {
		// crush data (average multiple rows together) if applicable
		// do this much more aggressively in safari, which is TERRIBLE at rendering complex SVGs
		var amount = 0;
		
		if (app.safari) {
			if (data.length >= 800) amount = 4;
			else if (data.length >= 600) amount = 3;
			else if (data.length >= 400) amount = 2;
		}
		else {
			// all other browsers only crush after 800 rows
			if (data.length >= 800) amount = 2;
		}
		
		// crush needed at all?
		if (amount < 2) return data;
		
		// crush time
		var new_data = [];
		var total = 0;
		var count = 0;
		
		for (var idx = 0, len = data.length; idx < len; idx++) {
			if (data[idx].y === null) {
				new_data.push( data[idx] );
			}
			else {
				total += data[idx].y;
				count++;
				if (count >= amount) {
					new_data.push({ x: data[idx].x, y: total / count });
					total = 0; count = 0;
				}
			}
		}
		if (count) {
			new_data.push({ x: data[ data.length - 1 ].x, y: total / count });
		}
		return new_data;
	},
	
	formatDataValue: function(value, mon_def) {
		// format single data value given monitor config definition
		var output = value;
		
		switch (mon_def.data_type) {
			case 'bytes': 
				output = get_text_from_bytes( Math.floor(value) ).replace(/bytes/, 'B');
			break;
			case 'seconds': output = get_text_from_seconds( Math.floor(value), true, true ); break;
			case 'milliseconds': output = commify( Math.floor(value) ); break;
			case 'integer': output = commify( Math.floor(value) ); break;
			case 'percent': output = '' + Math.floor(value); break;
			case 'string': output = value; break;
			default:
				if (output == Math.floor(output)) output = '' + output + '.0';
				else output = '' + short_float(output);
			break;
		}
		
		if (mon_def.suffix) output += mon_def.suffix;
		return output;
	},
	
	b64ToUint6: function(nChr) {
		// convert base64 encoded character to 6-bit integer
		// from: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Base64_encoding_and_decoding
		return nChr > 64 && nChr < 91 ? nChr - 65
			: nChr > 96 && nChr < 123 ? nChr - 71
			: nChr > 47 && nChr < 58 ? nChr + 4
			: nChr === 43 ? 62 : nChr === 47 ? 63 : 0;
	},

	base64DecToArr: function(sBase64, nBlocksSize) {
		// convert base64 encoded string to Uintarray
		// from: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Base64_encoding_and_decoding
		var sB64Enc = sBase64.replace(/[^A-Za-z0-9\+\/]/g, ""), nInLen = sB64Enc.length,
			nOutLen = nBlocksSize ? Math.ceil((nInLen * 3 + 1 >> 2) / nBlocksSize) * nBlocksSize : nInLen * 3 + 1 >> 2, 
			taBytes = new Uint8Array(nOutLen);
		
		for (var nMod3, nMod4, nUint24 = 0, nOutIdx = 0, nInIdx = 0; nInIdx < nInLen; nInIdx++) {
			nMod4 = nInIdx & 3;
			nUint24 |= this.b64ToUint6(sB64Enc.charCodeAt(nInIdx)) << 18 - 6 * nMod4;
			if (nMod4 === 3 || nInLen - nInIdx === 1) {
				for (nMod3 = 0; nMod3 < 3 && nOutIdx < nOutLen; nMod3++, nOutIdx++) {
					taBytes[nOutIdx] = nUint24 >>> (16 >>> nMod3 & 24) & 255;
				}
				nUint24 = 0;
			}
		}
		return taBytes;
	},
	
	copyGraphImage: function(elem) {
		// generate large offscreen graph, submit to server and copy URL to clipboard
		var self = this;
		var $elem = $(elem);
		var args = this.args;
		var $cont = $elem.closest('div.graph_container');
		var mon_id = $cont.data('mon');
		var mon_def = find_object( config.monitors, { id: mon_id } );
		var graph = this.graphs[mon_id];
		var combo_id = '';
		var group_id = '';
		
		// overview page uses a different ID system
		if (!graph && $cont.data('group')) {
			group_id = $cont.data('group');
			combo_id = group_id + '_' + mon_id;
			graph = this.graphs[combo_id];
		}
		
		// show indeterminate progress in icon
		$elem.removeClass().addClass('mdi mdi-clipboard-arrow-up-outline mdi-lg');
		
		// find right side of data for timestamp
		var max_x = 0;
		graph.w.config.series.forEach( function(dataset) {
			if (dataset.data && dataset.data.length && (dataset.data[dataset.data.length - 1].x > max_x)) {
				max_x = dataset.data[dataset.data.length - 1].x;
			}
		} );
		
		// get date stamp of right side of chart
		var dargs = get_date_args( new Date(max_x) );
		
		// generate title, path and filename
		var unique_id = get_unique_id(16, app.username);
		
		var title = mon_def.title;
		if (combo_id) {
			title = ucfirst( mon_def.merge_type ) + " " + mon_def.title;
		}
		if (args.hostname) {
			title += ' - ' + app.formatHostname(args.hostname);
		}
		else if (args.group) {
			if (app.getPref('ggt_' + mon_id)) {
				title = ucfirst( app.getPref('ggt_' + mon_id) ) + " " + mon_def.title;
			}
			var group_def = find_object( config.groups, { id: args.group } );
			if (group_def) title += ' - ' + group_def.title;
		}
		else if (group_id) {
			var group_def = find_object( config.groups, { id: group_id } );
			if (group_def) title += ' - ' + group_def.title;
		}
		
		var path = '';
		switch (args.sys) {
			case 'hourly':
				path = dargs.yyyy_mm_dd;
				title += ' - ' + get_nice_date(max_x / 1000);
				path += '/' + dargs.hh;
				title += ' - ' + dargs.hour12 + ' ' + dargs.ampm.toUpperCase();
			break;
			
			case 'daily':
				path = dargs.yyyy_mm_dd;
				title += ' - ' + get_nice_date(max_x / 1000);
			break;
			
			case 'monthly': 
				path = dargs.yyyy + '/' + dargs.mm; 
				var month = window._months[dargs.mon - 1][1];
				title += ' - ' + month + ' ' + dargs.year;
			break;
			
			case 'yearly': 
				path = dargs.yyyy;
				title += ' - ' + dargs.year;
			break;
			
			default:
				// i.e. overview page
				path = dargs.yyyy_mm_dd + '/' + dargs.hh;
				title += ' - ' + dargs.yyyy_mm_dd;
			break;
		} // sys
		
		if (args.hostname) path += '/' + args.hostname;
		else if (args.group) path += '/' + args.group;
		else if (group_id) path += '/' + group_id; // overview
		
		path += '/' + mon_id + '/' + unique_id + '.png';
		
		// copy final URL to clipboard
		var clip_url = config.base_app_url + '/files/' + path;
		copyToClipboard( clip_url );
		Debug.trace('upload', "URL copied to clipboard: " + clip_url);
		
		// hide some elements to avoid printing them on exported svg
		const xcrosshairs = graph.w.globals.dom.baseEl.querySelector( '.apexcharts-xcrosshairs' );
		const ycrosshairs = graph.w.globals.dom.baseEl.querySelector( '.apexcharts-ycrosshairs' );
		if (xcrosshairs) {
			xcrosshairs.setAttribute('x', -500);
			xcrosshairs.setAttribute('x1', -500);
			xcrosshairs.setAttribute('x2', -500);
		}
		if (ycrosshairs) {
			ycrosshairs.setAttribute('y', -100);
			ycrosshairs.setAttribute('y1', -100);
			ycrosshairs.setAttribute('y2', -100);
		}
		
		// can we get away with changing the title?
		var title_elem = graph.w.globals.dom.baseEl.querySelector( '.apexcharts-title-text' );
		var old_title = title_elem.innerHTML;
		title_elem.innerHTML = title;
		
		const w = graph.w;
		
		const canvas = document.createElement('canvas');
		canvas.width = w.globals.svgWidth * 2; // retina
		canvas.height = w.globals.svgHeight * 2; // retina
		
		var ctx = canvas.getContext('2d');
		ctx.scale(2, 2); // retina
		
		if (w.config.chart.background !== 'transparent') {
			ctx.fillStyle = w.config.chart.background;
			ctx.fillRect(0, 0, canvas.width, canvas.height);
		}
		
		var img = new Image();
		img.crossOrigin = 'anonymous';
		
		const svgData = w.globals.dom.Paper.svg();
		const svgUrl = 'data:image/svg+xml,' + encodeURIComponent(svgData);
		
		// reset title quickly
		title_elem.innerHTML = old_title;
		
		img.onload = function() {
			ctx.drawImage(img, 0, 0);
			var image_data_uri = canvas.toDataURL('image/png');
			
			// upload image to server
			var api_url = config.base_api_uri + '/app/upload_file' + compose_query_string({
				session_id: app.session_id,
				path: path
			});
			
			// extract raw base64 data from Data URI
			var raw_image_data = image_data_uri.replace(/^data\:image\/\w+\;base64\,/, '');
			
			Debug.trace('upload', "Uploading graph image to server: " + api_url);
			
			// contruct use AJAX object
			var http = new XMLHttpRequest();
			http.open("POST", api_url, true);
			
			// completion handler
			http.onload = function() {
				if (http.status != 200) {
					var code = http.status;
					var desc = http.statusText;
					Debug.trace( 'api', "Network Error: " + code + ": " + desc );
					app.doError( "Network Error: " + code + ": " + desc );
					
					// reset icon
					$elem.removeClass().addClass('mdi mdi-clipboard-pulse-outline mdi-lg');
					return;
				}
				
				var text = http.responseText;
				Debug.trace( 'api', "Received response from server: " + text );
				var resp = null;
				try { resp = JSON.parse(text); }
				catch (e) {
					// JSON parse error
					var desc = "JSON Error: " + e.toString();
					app.doError(desc);
					
					// reset icon
					$elem.removeClass().addClass('mdi mdi-clipboard-pulse-outline mdi-lg');
					return;
				}
				// success, but check json for server error code
				if (resp) {
					if (('code' in resp) && (resp.code != 0)) {
						// an error occurred within the JSON response
						app.doError("Error: " + resp.description);
						
						// reset icon
						$elem.removeClass().addClass('mdi mdi-clipboard-pulse-outline mdi-lg');
						return;
					}
				}
				
				// show success in icon
				$elem.removeClass().addClass('mdi mdi-clipboard-check-outline mdi-lg success');
			}; // http.onload
			
			// create a blob and decode our base64 to binary
			var blob = new Blob( [ self.base64DecToArr(raw_image_data) ], { type: 'image/png' } );
			
			// stuff into a form, so servers can easily receive it as a standard file upload
			var form = new FormData();
			form.append( 'file1', blob, 'upload.png' );
			
			// send data to server
			http.send(form);
		}; // img.onload
		
		img.src = svgUrl;
	},
	
	jumpToServer: function(hostname) {
		// jump to specific server detail page
		var args = this.args || {};
		if (!hostname) hostname = $('#fe_ctrl_server').val();
		
		// try to preserve as many args as possible
		args.hostname = hostname;
		delete args.group;
		delete args.cachebust;
		delete args.sub;
		delete args.id;
		
		if (args.date) {
			delete args.offset;
			delete args.length;
		}
		
		Nav.go( '#Server' + compose_query_string(args) );
		
		// reset "jump to" menu
		$('#fe_jump_to_server').val('');
	},
	
	jumpToGroup: function(group_id) {
		// jump to specific group detail page
		var args = this.args || {};
		if (!group_id) group_id = $('#fe_ctrl_group').val();
		
		// try to preserve as many args as possible
		args.group = group_id;
		delete args.hostname;
		delete args.cachebust;
		delete args.sub;
		delete args.id;
		
		if (args.date) {
			delete args.offset;
			delete args.length;
		}
		
		Nav.go( '#Group' + compose_query_string(args) );
		
		// reset "jump to" menu
		$('#fe_jump_to_group').val('');
	},
	
	navCtrlBack: function() {
		// jump backward in time
		var args = this.args;
		
		if (args.date) {
			// historical
			if ((args.sys == 'hourly') && args.date.match(/^(\d{4})\D+(\d{2})\D+(\d{2})\D+(\d{2})$/)) {
				// jump to previous day
				var yyyy = RegExp.$1;
				var mm = RegExp.$2;
				var dd = RegExp.$3;
				var hh = RegExp.$4;
				var epoch = get_time_from_args({
					year: parseInt(yyyy),
					mon: parseInt(mm),
					mday: parseInt(dd),
					hour: parseInt(hh),
					min: 0,
					sec: 0
				});
				var dargs = get_date_args( epoch - 1 );
				args.date = dargs.yyyy_mm_dd + '/' + dargs.hh;
			}
			else if ((args.sys == 'daily') && args.date.match(/^(\d{4})\D+(\d{2})\D+(\d{2})$/)) {
				// jump to previous day
				var yyyy = RegExp.$1;
				var mm = RegExp.$2;
				var dd = RegExp.$3;
				var epoch = get_time_from_args({
					year: parseInt(yyyy),
					mon: parseInt(mm),
					mday: parseInt(dd),
					hour: 0,
					min: 0,
					sec: 0
				});
				var dargs = get_date_args( epoch - 1 );
				args.date = dargs.yyyy_mm_dd;
			}
			else if ((args.sys == 'monthly') && args.date.match(/^(\d{4})\D(\d{2})$/)) {
				// jump to previous month
				var yyyy = RegExp.$1;
				var mm = RegExp.$2;
				var epoch = get_time_from_args({
					year: parseInt(yyyy),
					mon: parseInt(mm),
					mday: 1,
					hour: 0,
					min: 0,
					sec: 0
				});
				var dargs = get_date_args( epoch - 1 );
				args.date = dargs.yyyy + '/' + dargs.mm;
			}
			else if ((args.sys == 'yearly') && args.date.match(/^(\d{4})$/)) {
				// jump to previous year
				var yyyy = parseInt( RegExp.$1 );
				yyyy--;
				if (yyyy < config.first_year) return;
				args.date = '' + yyyy;
			}
			
			delete args.offset;
			delete args.length;
		}
		else {
			// live, switch to hourly historical
			var dargs = get_date_args( time_now() - 3600 );
			args.sys = 'hourly';
			args.date = dargs.yyyy_mm_dd + '/' + dargs.hh;
			delete args.offset;
			delete args.length;
		}
		
		this.navToArgs();
	},
	
	navCtrlForward: function() {
		// jump forward in time
		var args = this.args;
		
		if (args.date) {
			// historical
			var max_epoch = normalize_time( time_now(), { min: 0, sec: 0 } );
			
			if ((args.sys == 'hourly') && args.date.match(/^(\d{4})\D+(\d{2})\D+(\d{2})\D+(\d{2})$/)) {
				// jump to next hour
				var yyyy = RegExp.$1;
				var mm = RegExp.$2;
				var dd = RegExp.$3;
				var hh = RegExp.$4;
				var epoch = get_time_from_args({
					year: parseInt(yyyy),
					mon: parseInt(mm),
					mday: parseInt(dd),
					hour: parseInt(hh),
					min: 59,
					sec: 59
				});
				epoch++;
				if (epoch >= max_epoch) {
					// switch to realtime hourly
					delete args.date;
					args.offset = -60;
					args.length = 60;
					this.navToArgs();
					return;
				}
				else {
					var dargs = get_date_args( epoch );
					args.date = dargs.yyyy_mm_dd + '/' + dargs.hh;
				}
			}
			else if ((args.sys == 'daily') && args.date.match(/^(\d{4})\D+(\d{2})\D+(\d{2})$/)) {
				// jump to next day
				var yyyy = RegExp.$1;
				var mm = RegExp.$2;
				var dd = RegExp.$3;
				var epoch = get_time_from_args({
					year: parseInt(yyyy),
					mon: parseInt(mm),
					mday: parseInt(dd),
					hour: 23,
					min: 59,
					sec: 59
				});
				epoch++;
				if (epoch > max_epoch) return;
				var dargs = get_date_args( epoch );
				args.date = dargs.yyyy_mm_dd;
			}
			else if ((args.sys == 'monthly') && args.date.match(/^(\d{4})\D(\d{2})$/)) {
				// jump to next month
				var yyyy = RegExp.$1;
				var mm = RegExp.$2;
				yyyy = parseInt(yyyy);
				mm = parseInt(mm);
				mm++; if (mm > 12) { mm = 1; yyyy++; }
				var epoch = get_time_from_args({
					year: yyyy,
					mon: mm,
					mday: 1,
					hour: 0,
					min: 0,
					sec: 0
				});
				if (epoch > max_epoch) return;
				var dargs = get_date_args( epoch );
				args.date = dargs.yyyy + '/' + dargs.mm;
			}
			else if ((args.sys == 'yearly') && args.date.match(/^(\d{4})$/)) {
				// jump to next year
				var yyyy = parseInt( RegExp.$1 );
				yyyy++;
				if (yyyy > yyyy()) return;
				args.date = '' + yyyy;
			}
			
			delete args.offset;
			delete args.length;
		}
		else {
			// live (no-op)
			return;
		}
		
		this.navToArgs();
	},
	
	renderGroupSelector: function(dom_prefix, cur_value) {
		// render expanding checkbox list for multi-group selection
		// provide an "All Groups" checkbox which collapses list
		var html = '';
		var group_is_all = (cur_value == '.+');
		
		// convert regexp match into hash of group ids
		var groups_selected = {};
		cur_value.split(/\W+/).forEach( function(group_id) {
			if (group_id.match(/^\w+$/)) groups_selected[group_id] = true;
		});
		
		html += '<div class="group_sel_wrapper">';
		
		// all groups checkbox
		html += '<div class="priv_group_admin">';
		html += '<input type="checkbox" id="' + dom_prefix + '_all" value="1" ' + 
			(group_is_all ? 'checked="checked" ' : '') + 'onChange="$P().toggleGroupSelectorAll(this)">';
		html += '<label for="' + dom_prefix + '_all">All Groups</label>';
		html += '</div>';
		
		// individual groups
		for (var idx = 0, len = config.groups.length; idx < len; idx++) {
			var group = config.groups[idx];
			var has_group = !!groups_selected[ group.id ];
			var group_disabled = !!group_is_all;
			
			html += '<div class="priv_group_other">';
			html += '<input type="checkbox" id="' + dom_prefix + '_group_' + group.id + '" value="1" ' + 
				(has_group ? 'checked="checked" ' : '') + ' ' + (group_disabled ? 'disabled="disabled"' : '') + '>';
			html += '<label for="' + dom_prefix + '_group_' + group.id + '">' + group.title + '</label>';
			html += '</div>';
		}
		
		html += '</div>'; // wrapper
		
		return html;
	},
	
	toggleGroupSelectorAll: function(elem) {
		// toggle "All Groups" checkbox, swap visibility of group list
		var is_checked = $(elem).is(':checked');
		/*if (is_checked) this.div.find('div.priv_group_other').hide(250);
		else this.div.find('div.priv_group_other').show(250);*/
		if (is_checked) {
			this.div.find('div.priv_group_other > input').attr('disabled', true);
		}
		else {
			this.div.find('div.priv_group_other > input').removeAttr('disabled');
		}
	},
	
	getGroupSelectorValue: function(dom_prefix) {
		// get selection of all checkbox in group list, return regexp match string
		if (this.div.find('#' + dom_prefix + '_all').is(':checked')) return '.+';
		
		var group_list = [];
		for (var idx = 0, len = config.groups.length; idx < len; idx++) {
			var group = config.groups[idx];
			if (this.div.find('#' + dom_prefix + '_group_' + group.id).is(':checked')) {
				group_list.push( group.id );
			}
		}
		
		if (!group_list.length) return '(?!)'; // never match
		return '^(' + group_list.join('|') + ')$';
	},
	
	initQueue: function() {
		// setup for queue system
		this.queue = [];
		this.queueIndex = {};
		delete this.queueTimer;
	},
	
	enqueue: function(handler, id) {
		// simple queue system, invokes handler once per N milliseconds (default 10)
		if (!this.queue) this.queue = [];
		var item = {
			handler: handler,
			id: id || ''
		};
		
		if (id) {
			if (!this.queueIndex) this.queueIndex = {};
			if (this.queueIndex[id]) return; // dupe, silently skip
			this.queueIndex[id] = item;
		}
		
		this.queue.push(item);
		
		if (!this.queueTimer) {
			this.queueTimer = setTimeout( this.dequeue.bind(this), this.queueDelay );
		}
	},
	
	dequeue: function() {
		// dequeue single item and launch it
		delete this.queueTimer;
		
		var item = this.queue.shift();
		if (!item) return;
		if (item.id) delete this.queueIndex[item.id];
		
		item.handler();
		
		if (this.queue.length && !this.queueTimer) {
			this.queueTimer = setTimeout( this.dequeue.bind(this), this.queueDelay );
		}
	},
	
	isRealTime: function() {
		// return true if current page is in realtime mode, false otherwise
		var args = this.args;
		if (!args.date && (args.sys == 'hourly') && (args.offset == 0 - args.length)) {
			return true;
		}
		else {
			return false;
		}
	},
	
	showHostDataExplorer: function($elem) {
		// show dialog allowing user to explore the JSON data from servers
		// and pick a particular key, which will populate a text field using [data/path] syntax
		var self = this;
		var html = '';
		if (typeof($elem) == 'string') $elem = $($elem);
		
		if (!num_keys(app.recent_hostnames)) {
			return app.doError("Sorry, no servers have sent any data into the system yet.");
		}
		
		html += '<div style="width:500px; font-size:12px; margin-bottom:20px;">';
		html += "Use this tool to help locate a specific server metric, by exploring the actual data being sent in by your servers.  Click on any metric key below to construct a correct <code>[data/path]</code> and insert it back into the form field.";
		html += '</div>';
		
		html += '<center><table>' + 
			// get_form_table_spacer() + 
			get_form_table_row('Server:', '<select id="fe_explore_server" onChange="$P().populateHostDataExplorer($(this).val())">' + app.getRecentServerMenuOptionsHTML() + '</select>') + 
			get_form_table_caption("Select the server hostname to explore metrics for.");
			// get_form_table_spacer('transparent');
		
		html += '<tr><td colspan="2"><div id="d_explore_area" class="explore_area"></div></td></tr>';
		
		html += // get_form_table_spacer('transparent') + 
			get_form_table_row('Selection:', '<input type="text" id="fe_explore_sel" class="mono" style="width:300px">') + 
			get_form_table_caption("Your formatted selection will appear here.");
		
		html += '</table></center>';
		
		app.customConfirm( '<i class="fa fa-search">&nbsp;</i>Server Data Explorer', html, "Apply", function(result) {
			app.clearError();
			
			if (result) {
				var text_to_insert = $('#fe_explore_sel').val();
				var text = $elem.val().trim();
				if (text.length) text += " ";
				text += text_to_insert;
				Dialog.hide();
				$elem.focus().val('').val( text ); // this trick places the caret at the end
			} // user clicked yes
		} ); // app.confirm
		
		this.populateHostDataExplorer( $('#fe_explore_server').val() || first_key(app.recent_hostnames) );
	},
	
	populateHostDataExplorer: function(hostname) {
		// fetch data for specific server and populate explorer dialog
		var self = this;
		var $cont = $('#d_explore_area');
		$cont.empty().addClass('loading');
		
		app.api.get( 'app/view/verbose', { hostname: hostname }, function(resp) {
			// got data, format into tree
			var html = '';
			var metadata = resp.metadata;
			var branches = [{ path: "", key: "", value: metadata.data, indent: -1 }];
			
			while (branches.length) {
				var branch = branches.shift();
				var indent_px = Math.max(0, branch.indent) * 20;
				
				if (branch.value && (typeof(branch.value) == 'object')) {
					if (branch.key) {
						html += '<div class="explore_item" style="margin-left:' + indent_px + 'px"><i class="fa fa-folder-open-o">&nbsp;</i><b>' + branch.key + '</b></div>';
					}
					hash_keys_to_array(branch.value).sort( function(a, b) {
						var ta = typeof( branch.value[a] );
						var tb = typeof( branch.value[b] );
						if ((ta == 'object') && (tb != 'object')) return -1;
						else if ((ta != 'object') && (tb == 'object')) return 1;
						else return a.localeCompare(b);
					} ).reverse().forEach( function(key) {
						branches.unshift({ 
							path: branch.path + '/' + branch.key, 
							key: key, 
							value: branch.value[key], 
							indent: branch.indent + 1 
						});
					});
				}
				else {
					html += '<div class="explore_item" style="margin-left:' + indent_px + 'px"><span class="link" data-path="' + branch.path + '/' + branch.key + '" onMouseUp="$P().pickHostDataKey(this)"><i class="fa fa-file-o">&nbsp;</i><b>' + branch.key + '</b></span>:&nbsp;' + JSON.stringify(branch.value) + '</div>';
				}
			}
			
			$cont.removeClass('loading').html( html );
		}, 
		function(err) {
			$cont.removeClass('loading').html(
				'<div style="line-height:300px; text-align:center">' + err.description  + '</div>' 
			);
		} );
	},
	
	pickHostDataKey: function(elem) {
		// user clicked on a host data explorer JSON path key
		// populate it into the staging text area
		var path = $(elem).data('path').replace(/\/+/g, '/').replace(/^\//, '');
		$('#fe_explore_sel').val( '[' + path + ']' ).focus();
	},
	
	getPercentBarHTML: function(amount, width) {
		// render simple percentage bar with green / yellow / red colors
		var html = '';
		html += '<div class="percent_bar_container" style="width:' + width + 'px" title="' + pct(amount) + '">';
		
		var color = '';
		if (amount >= 0.75) color = 'rgba(255, 0, 0, 0.75)';
		else if (amount >= 0.5) color = 'rgba(224, 224, 0, 0.85)';
		else color = '#080';
		
		var color_width = Math.floor( amount * width );
		html += '<div class="percent_bar_inner" style="background-color:' + color + '; width:' + color_width + 'px"></div>';
		html += '</div>';
		return html;
	},
	
	getCPUTableHTML: function(cpus) {
		// render HTML for CPU detail table
		var self = this;
		var html = '';
		html += '<legend>CPU Details</legend>';
		html += '<table class="fieldset_table" width="100%">';
		html += '<tr>';
			html += '<th>CPU #</th>';
			html += '<th>System %</th>';
			html += '<th>User %</th>';
			html += '<th>Nice %</th>';
			html += '<th>I/O Wait %</th>';
			html += '<th>Hard IRQ %</th>';
			html += '<th>Soft IRQ %</th>';
			html += '<th>Total %</th>';
		html += '</tr>';
		
		var cpu_list = [];
		for (var idx = 0, len = num_keys(cpus); idx < len; idx++) {
			var key = 'cpu' + idx;
			if (cpus[key]) cpu_list.push( cpus[key] );
		}
		
		cpu_list.forEach( function(cpu, idx) {
			html += '<tr>';
			html += '<td><b>#' + Math.floor( idx + 1 ) + '</b></td>';
			html += '<td>' + pct( cpu.system || 0, 100 ) + '</td>';
			html += '<td>' + pct( cpu.user || 0, 100 ) + '</td>';
			html += '<td>' + pct( cpu.nice || 0, 100 ) + '</td>';
			html += '<td>' + pct( cpu.iowait || 0, 100 ) + '</td>';
			html += '<td>' + pct( cpu.irq || 0, 100 ) + '</td>';
			html += '<td>' + pct( cpu.softirq || 0, 100 ) + '</td>';
			
			var total = 100 - (cpu.idle || 0);
			html += '<td>' + self.getPercentBarHTML( total / 100, 200 ) + '</td>';
			html += '</tr>';
		});
		
		html += '</table>';
		return html;
	},
	
	getBasicTable: function() {
		// get html for sorted table (fake pagination, for looks only)
		// overriding function in page.js for adding ids per row
		var html = '';
		var args = null;
		
		if (arguments.length == 1) {
			// custom args calling convention
			args = arguments[0];
		}
		else {
			// classic calling convention
			args = {
				rows: arguments[0],
				cols: arguments[1],
				data_type: arguments[2],
				callback: arguments[3]
			};
		}
		
		var rows = args.rows;
		var cols = args.cols;
		var data_type = args.data_type;
		var callback = args.callback;
		
		// pagination
		html += '<div class="pagination">';
		html += '<table cellspacing="0" cellpadding="0" border="0" width="100%"><tr>';
		
		html += '<td align="left" width="33%">';
		if (cols.headerLeft) html += cols.headerLeft;
		else html += commify(rows.length) + ' ' + pluralize(data_type, rows.length) + '';
		html += '</td>';
		
		html += '<td align="center" width="34%">';
			html += cols.headerCenter || '&nbsp;';
		html += '</td>';
		
		html += '<td align="right" width="33%">';
			html += cols.headerRight || 'Page 1 of 1';
		html += '</td>';
		
		html += '</tr></table>';
		html += '</div>';
		
		html += '<div style="margin-top:5px;">';
		
		var tattrs = args.attribs || {};
		if (!tattrs.class) tattrs.class = 'data_table ellip';
		if (!tattrs.width) tattrs.width = '100%';
		html += '<table ' + compose_attribs(tattrs) + '>';
		
		html += '<tr><th style="white-space:nowrap;">' + cols.join('</th><th style="white-space:nowrap;">') + '</th></tr>';
		
		for (var idx = 0, len = rows.length; idx < len; idx++) {
			var row = rows[idx];
			var tds = callback(row, idx);
			if (tds.insertAbove) html += tds.insertAbove;
			html += '<tr' + (tds.className ? (' class="'+tds.className+'"') : '') + (row.id ? (' data-id="'+row.id+'"') : '') + '>';
			html += '<td>' + tds.join('</td><td>') + '</td>';
			html += '</tr>';
		} // foreach row
		
		if (!rows.length) {
			html += '<tr><td colspan="'+cols.length+'" align="center" style="padding-top:10px; padding-bottom:10px; font-weight:bold;">';
			html += 'No '+pluralize(data_type)+' found.';
			html += '</td></tr>';
		}
		
		html += '</table>';
		html += '</div>';
		
		return html;
	},
	
	setupDraggableTable: function(args) {
		// allow table rows to be drag-sorted
		// args: { table_sel, handle_sel, drag_ghost_sel, drag_ghost_x, drag_ghost_y, callback }
		var $table = $(args.table_sel);
		var $rows = $table.find('tr').slice(1); // omit header row
		var $cur = null;
		
		var createDropZone = function($tr, idx, pos) {
			pos.top -= Math.floor( pos.height / 2 );
			
			$('<div><div class="dz_bar"></div></div>')
				.addClass('dropzone')
				.css({
					left: '' + pos.left + 'px',
					top: '' + pos.top + 'px',
					width: '' + pos.width + 'px',
					height: '' + pos.height + 'px'
				})
				.appendTo('body')
				.on('dragover', function(event) {
					var e = event.originalEvent;
					e.preventDefault();
					e.dataTransfer.effectAllowed = "move";
				})
				.on('dragenter', function(event) {
					var e = event.originalEvent;
					e.preventDefault();
					$(this).addClass('drag');
				})
				.on('dragleave', function(event) {
					$(this).removeClass('drag');
				})
				.on('drop', function(event) {
					var e = event.originalEvent;
					e.preventDefault();
					
					// make sure we didn't drop on ourselves
					if (idx == $cur.data('drag_idx')) return false;
					
					// see if we need to insert above or below target
					var above = true;
					var pos = $tr.offset();
					var height = $tr.height();
					var y = event.clientY;
					if (y > pos.top + (height / 2)) above = false;
					
					// remove element being dragged
					$cur.detach();
					
					// insert at new location
					if (above) $tr.before( $cur );
					else $tr.after( $cur );
					
					// fire callback, pass new sorted collection
					args.callback( $table.find('tr').slice(1) );
				});
		}; // createDropZone
		
		$rows.each( function(row_idx) {
			var $handle = $(this).find(args.handle_sel);
			
			$handle.on('dragstart', function(event) {
				var e = event.originalEvent;
				var $tr = $cur = $(this).closest('tr');
				var $ghost = $tr.find(args.drag_ghost_sel).addClass('dragging');
				var ghost_x = ('drag_ghost_x' in args) ? args.drag_ghost_x : Math.floor($ghost.width() / 2);
				var ghost_y = ('drag_ghost_y' in args) ? args.drag_ghost_y : Math.floor($ghost.height() / 2);
				
				e.dataTransfer.setDragImage( $ghost.get(0), ghost_x, ghost_y );
				e.dataTransfer.effectAllowed = 'move';
				e.dataTransfer.setData('text/html', 'blah'); // needed for FF.
				
				// need to recalc $rows for each drag
				$rows = $table.find('tr').slice(1);
				
				$rows.each( function(idx) {
					var $tr = $(this);
					$tr.data('drag_idx', idx);
				});
				
				// and we need to recalc row_idx too
				var row_idx = $tr.data('drag_idx');
				
				// create drop zones for each row
				// (except those immedately surrounding the row we picked up)
				$rows.each( function(idx) {
					var $tr = $(this);
					if ((idx != row_idx) && (idx != row_idx + 1)) {
						var pos = $tr.offset();
						pos.width = $tr.width();
						pos.height = $tr.height();
						createDropZone( $tr, idx, pos );
					}
				});
				
				// one final zone below table (possibly)
				if (row_idx != $rows.length - 1) {
					var $last_tr = $rows.slice(-1);
					var pos = $last_tr.offset();
					pos.width = $last_tr.width();
					pos.height = $last_tr.height();
					pos.top += pos.height;
					createDropZone( $last_tr, $rows.length, pos );
				}
			}); // dragstart
			
			$handle.on('dragend', function(event) {
				// cleanup drop zones
				$('div.dropzone').remove();
				$rows.removeData('drag_idx');
				$table.find('.dragging').removeClass('dragging');
			}); // dragend
			
		} ); // foreach row
	},
	
	cancelDrag: function(table_sel) {
		// cancel drag operation in progress (well, as best we can)
		var $table = $(table_sel);
		if (!$table.length) return;
		
		var $rows = $table.find('tr').slice(1); // omit header row
		$('div.dropzone').remove();
		$rows.removeData('drag_idx');
		$table.find('.dragging').removeClass('dragging');
	}
	
} );

Class.subclass( Page.Base, "Page.Home", {	
	
	onInit: function() {
		// called once at page load
		var html = '';
		this.div.html( html );
	},
	
	onActivate: function(args) {
		// page activation
		if (!this.requireLogin(args)) return true;
		
		if (!args) args = {};
		this.args = args;
		
		if (!args.length) {
			// default to last hour
			args.offset = -60;
			args.length = 60;
		}
		
		app.setWindowTitle('Overview');
		app.showTabBar(true);
		this.showControls(true);
		
		// data range (will be filled in later)
		$('#d_ctrl_range').show().find('.info_value').html('');
		
		if (this.div.is(':empty')) {
			this.div.addClass('loading');
		}
		
		this.groups = null;
		this.graphs = null;
		this.requestData();
		return true;
	},
	
	requestData: function() {
		// request data for this view
		var self = this;
		var args = this.args;
		
		app.api.get( 'app/overview', args, this.receiveData.bind(this), function(err) {
			if (err.code == "no_data") self.doInlineError( "No Data Found", "No data was found in the specified time range." );
			else self.doInlineError( "Server Error", err.description );
		} );
	},
	
	receiveData: function(data) {
		// receive view data from server
		// data: { code, rows, alerts }
		var self = this;
		var args = this.args;
		this.div.removeClass('loading');
		this.rows = data.rows;
		this.alerts = data.alerts;
		
		if (!this.rows.length) {
			return this.doInlineError('No Data Found', 'No data was found in the specified time range.');
		}
		
		// figure out which groups we actually have data for
		this.groups = [];
		var all_groups = {};
		var group_server_ranges = {};
		
		this.rows.forEach( function(row) {
			if (row.groups) {
				for (var group_id in row.groups) {
					all_groups[group_id] = 1;
					
					var count = row.groups[group_id].count || 0;
					if (count) {
						if (!(group_id in group_server_ranges)) {
							group_server_ranges[group_id] = { max: 0, min: 999999 };
						}
						if (count > group_server_ranges[group_id].max) group_server_ranges[group_id].max = count;
						if (count < group_server_ranges[group_id].min) group_server_ranges[group_id].min = count;
					}
				}
			}
		});
		if (!num_keys(all_groups)) {
			return this.doInlineError('No Data Found', 'No data was found in the specified time range.');
		}
		for (var group_id in all_groups) {
			var group_def = find_object( config.groups, { id: group_id } );
			if (group_def) this.groups.push( group_def );
		}
		this.groups.sort( function(a, b) {
			return (a.sort_order < b.sort_order) ? -1 : 1;
		} );
		
		// build HTML for page
		var html = '';
		
		// insert alerts and server info here
		// (will be populated later)
		html += '<fieldset id="fs_overview_alerts" style="margin-top:10px; display:none"></fieldset>';
		
		// for when all graphs are filtered out:
		html += '<fieldset class="inline_error" id="fs_all_filtered" style="display:none">';
		html += '<div class="inline_error_title">All Graphs Filtered</div>';
		html += '<div class="inline_error_msg">Please enter a different filter query.</div>';
		html += '</fieldset>';
		
		// render special fieldset for each group
		// in custom sort order
		this.groups.forEach( function(group_def) {
			var monitors = app.findMonitorsFromGroup( group_def );
			if (!monitors.length) return;
			
			html += '<fieldset class="overview_group">';
			html += '<legend>' + self.getNiceGroup(group_def);
			if (group_server_ranges[group_def.id].max) {
				html += '<span class="ov_group_legend_count">(';
				if (group_server_ranges[group_def.id].min != group_server_ranges[group_def.id].max) {
					// server counts varied across range
					html += commify(group_server_ranges[group_def.id].min) + ' - ' + 
						+ commify(group_server_ranges[group_def.id].max) + ' servers';
				}
				else {
					// consistent number of servers across range
					html += commify(group_server_ranges[group_def.id].min) + ' ' + 
						pluralize('server', group_server_ranges[group_def.id].min);
				}
				html += ')</span>';
			}
			html += '</legend>';
			
			// now insert empty graphs for each monitor in group
			html += '<div class="graphs overview size_' + app.getPref('ov_graph_size') + '">';
			
			// graph placeholders
			monitors.forEach( function(mon_def) {
				if (!mon_def.merge_type) return;
				var combo_id = group_def.id + '_' + mon_def.id;
				html += '<div id="d_graph_ov_' + combo_id + '" class="graph_container" data-group="' + group_def.id + '" data-mon="' + mon_def.id + '" style="min-height:200px;">'; // hack
				html += '<div class="graph_button copy"><i class="mdi mdi-clipboard-pulse-outline mdi-lg" title="Copy Graph Image URL" onMouseUp="$P().copyGraphImage(this)"></i></div>';
				html += '<div id="c_graph_ov_' + combo_id + '"></div>';
				html += '</div>';
			}); // foreach monitor
			
			html += '<div class="clear"></div>';
			html += '</div>';
			
			html += '</fieldset>';
		}); // foreach group
		
		this.div.html(html);
		
		// create all graphs without data
		this.graphs = {};
		
		/*
		this.groups.forEach( function(group_def) {
			var monitors = app.findMonitorsFromGroup( group_def );
			if (!monitors.length) return;
			
			monitors.forEach( function(mon_def, idx) {
				if (!mon_def.merge_type) return;
				var combo_id = group_def.id + '_' + mon_def.id;
				
				self.graphs[combo_id] = self.createGraph({
					id: combo_id,
					title: ucfirst(mon_def.merge_type) + " " + mon_def.title,
					data_type: mon_def.data_type,
					merge_type: mon_def.merge_type,
					suffix: mon_def.suffix || '',
					num_layers: 1,
					canvas_id: 'c_graph_ov_' + combo_id,
					color: self.graphColors[ idx % self.graphColors.length ]
				});
			}); // foreach monitor
		}); // foreach group
		*/
		
		// calculate min/max for data bounds
		this.calcDataRange();
		
		// update and render data range display in control strip
		this.updateDataRangeDisplay();
		
		// apply filters if any
		this.applyMonitorFilter(true);
		
		// trigger visible graph redraw (also happens on debounced scroll)
		this.div.find('div.graph_container').addClass('dirty');
		this.onScrollDebounce();
		this.updateInfo();
	},
	
	calcDataRange: function() {
		// calculate min/max for data bounds
		var args = this.args;
		var now_minute = Math.floor( time_now() / 60 ) * 60;
		this.range_min = (now_minute + (args.offset * 60)) * 1000;
		this.range_max = (now_minute + (args.offset * 60) + (args.length * 60)) * 1000;
	},
	
	isRowInRange: function(row) {
		// calculate if row.date is within our range bounds
		if (this.range_min && (row.date < this.range_min / 1000)) return false;
		if (this.range_max && (row.date > this.range_max / 1000)) return false;
		return true;
	},
	
	updateDataRangeDisplay: function() {
		// scan current dataset for min/max epoch and render data range in control strip
		var self = this;
		var min_date = 0;
		var max_date = 0;
		
		this.rows.forEach( function(row) {
			if (self.isRowInRange(row)) {
				if (!min_date || (row.date < min_date)) min_date = row.date;
				if (!max_date || (row.date > max_date)) max_date = row.date;
			}
		});
		
		// display data range
		this.displayDataRange( min_date, max_date );
	},
	
	updateGraph: function(group_id, mon_id) {
		// update single graph
		// called on dequeue
		var self = this;
		var combo_id = group_id + '_' + mon_id;
		var graph = this.graphs[combo_id];
		var graph_rows = [];
		
		// see if graph is still visible (queue delay -- user could have scrolled past)
		if (!this.div.find('#d_graph_ov_' + combo_id).visible(true, true)) {
			this.div.find('#d_graph_ov_' + combo_id).addClass('dirty');
			return;
		}
		
		// var group_def = find_object( config.groups, { id: group_id } );
		var mon_def = find_object( config.monitors, { id: mon_id } );
		
		if (!graph) {
			// first time graph scrolled into view, so create it
			var mon_idx = find_object_idx( config.monitors, { id: mon_id } );
			graph = this.graphs[combo_id] = self.createGraph({
				id: combo_id,
				title: ucfirst(mon_def.merge_type) + " " + mon_def.title,
				data_type: mon_def.data_type,
				merge_type: mon_def.merge_type,
				suffix: mon_def.suffix || '',
				num_layers: 1,
				canvas_id: 'c_graph_ov_' + combo_id,
				color: this.graphColors[ mon_idx % this.graphColors.length ]
			});
		}
		
		// process each row
		this.rows.forEach( function(row) {
			var group = row.groups ? row.groups[group_id] : null;
			if (group && group.totals && (mon_id in group.totals) && self.isRowInRange(row)) {
				var value = group.totals[mon_id];
				if (mon_def.merge_type == 'avg') value /= group.count || 1;
				graph_rows.push({ x: row.date * 1000, y: value });
			} // in range
		});
		
		// setup chart series
		var series = [{
			name: ucfirst( mon_def.merge_type.replace(/avg/, 'average') ),
			data: self.crushData( graph_rows )
		}];
		
		// redraw graph series and annos
		var options = this.getGraphConfig(combo_id);
		options.series = series;
		graph.updateOptions(options, true, false);
	},
	
	onScrollDebounce: function(instant) {
		// called for redraw, and for scroll (debounced)
		// find all graphs which are dirty AND visible, and update them
		var self = this;
		
		this.div.find('div.graph_container.dirty').each( function() {
			var $this = $(this);
			if (!$this.hasClass('filtered') && $this.visible(true, true)) {
				var group_id = $this.data('group');
				var mon_id = $this.data('mon');
				var combo_id = group_id + '_' + mon_id;
				Debug.trace('graph', "Rendering graph for scroll event: " + combo_id );
				$this.removeClass('dirty');
				
				// reset copy icon, just in case
				$this.find('div.graph_button.copy > i').removeClass().addClass('mdi mdi-clipboard-pulse-outline mdi-lg');
				
				if (instant) self.updateGraph(group_id, mon_id);
				else self.enqueue( self.updateGraph.bind(self, group_id, mon_id), combo_id );
			}
		});
	},
	
	onSecond30: function(dargs) {
		// update graphs on the :30s, but only in realtime view
		var args = this.args;
		
		if (this.isRealTime() && (app.getPref('auto_refresh') == '1')) {
			// special case: if we are in an error state, perform a full refresh
			if (!this.graphs) return this.requestData();
			
			var temp_args = copy_object(args);
			temp_args.offset = -1;
			temp_args.length = 1;
			Debug.trace("Requesting graph update on the 30s");
			
			app.api.get( 'app/overview', temp_args, this.receiveUpdate.bind(this), function(err) {
				app.doError( "Server Error: " + err.description );
			} );
		}
	},
	
	onFocus: function() {
		// window received focus, update data
		var args = this.args;
		
		if (this.isRealTime() && (app.getPref('auto_refresh') == '1')) {
			// special case: if we are in an error state, perform a full refresh
			if (!this.graphs) return this.requestData();
			
			Debug.trace("Requesting graph update for focus");
			
			app.api.get( 'app/overview', args, this.receiveUpdate.bind(this), function(err) {
				app.doError( "Server Error: " + err.description );
			} );
		}
	},
	
	receiveUpdate: function(data) {
		// receive update from server
		// data: { code, rows, alerts }
		var self = this;
		var rows = data.rows;
		var args = this.args;
		
		this.alerts = data.alerts;
		
		if (!rows.length) {
			Debug.trace("No rows found in update, skipping");
			return;
		}
		
		// skip dupes
		var new_rows = [];
		rows.forEach( function(row) {
			if (!find_object(self.rows, { date: row.date })) new_rows.push(row);
		});
		rows = new_rows;
		
		if (!rows.length) {
			Debug.trace("All rows were dupes in update, skipping");
			return;
		}
		
		rows.forEach( function(row) {
			self.rows.push( row );
		});
		
		// sort just in case
		this.rows = this.rows.sort( function(a, b) {
			return (a.date - b.date);
		});
		
		// discard old if beyond length
		while (this.rows.length > args.length) this.rows.shift();
		
		// we need to apply range minimum and maximum again, because time moves forward
		this.calcDataRange();
		
		// update and render data range display in control strip
		this.updateDataRangeDisplay();
		
		// trigger visible graph redraw (also happens on debounced scroll)
		this.div.find('div.graph_container').addClass('dirty');
		this.onScrollDebounce();
		this.updateInfo();
	},
	
	updateInfo: function() {
		// show alerts info
		var self = this;
		
		if (!this.isRealTime() || !this.alerts || !this.alerts.hostnames) {
			this.div.find('#fs_overview_alerts').empty().hide();
			return;
		}
		
		var all_alerts = [];
		for (var hostname in this.alerts.hostnames) {
			var host_alerts = this.alerts.hostnames[hostname];
			for (var alert_id in host_alerts) {
				var alert = host_alerts[alert_id];
				var group_def = app.findGroupFromHostname( hostname );
				
				all_alerts.push( merge_objects( alert, {
					id: alert_id,
					group_id: group_def ? group_def.id : '',
					hostname: hostname
				} ) );
			} // foreach alert
		} // foreach hostname
		
		if (!all_alerts.length) {
			this.div.find('#fs_overview_alerts').empty().hide();
			return;
		}
		
		// sort by alert ID, then by hostname
		all_alerts = all_alerts.sort( function(a, b) {
			return (a.id == b.id) ? a.hostname.localeCompare(b.hostname) : a.id.localeCompare( b.id );
		} );
		
		// build alert table
		var html = '';
		html += '<legend style="color:red">Current Alerts</legend>';
		html += '<table class="fieldset_table" width="100%">';
		html += '<tr>';
			html += '<th>Alert</th>';
			html += '<th>Hostname</th>';
			html += '<th>Group</th>';
			html += '<th>Detail</th>';
			html += '<th>Trigger</th>';
			html += '<th>Date/Time</th>';
			html += '<th>Actions</th>';
		html += '</tr>';
		
		all_alerts.forEach( function(alert) {
			var alert_def = find_object( config.alerts, { id: alert.id } ) || { 
				id: alert.id,
				title: '(' + alert.id + ')',
				expression: 'n/a'
			};
			var group_def = alert.group_id ? find_object( config.groups, { id: alert.group_id } ) : null;
			
			html += '<tr>';
			html += '<td><b>' + self.getNiceAlert(alert_def, true) + '</b></td>';
			html += '<td>' + self.getNiceHostname(alert.hostname, true) + '</td>';
			html += '<td>' + self.getNiceGroup(group_def) + '</td>';
			html += '<td>' + alert.message + '</td>';
			html += '<td style="font-family:monospace">' + alert_def.expression + '</pre></td>';
			html += '<td>' + get_nice_date_time( alert.date ) + '</td>';
			
			var snap_id = alert.hostname + '/' + Math.floor( alert.date / 60 );
			html += '<td><a href="#Snapshot?id=' + snap_id + '">View&nbsp;Snapshot</a></td>';
			
			html += '</tr>';
		});
		
		html += '</table>';
		this.div.find('#fs_overview_alerts').empty().html(html).show();
	},
	
	getNiceGroup: function(item) {
		// get formatted group with icon, plus optional link
		var link = true;
		var html = '';
		if (!item) return '(None)';
		
		var query = { group: item.id };
		if (this.args && ('offset' in this.args)) query.offset = this.args.offset;
		if (this.args && this.args.length) query.length = this.args.length;
		
		var icon = '<i class="mdi mdi-server-network">&nbsp;</i>';
		if (link) {
			html += '<a href="#Group' + compose_query_string(query) + '" style="text-decoration:none">';
			html += icon + '<span style="text-decoration:underline">' + item.title + '</span></a>';
		}
		else {
			html += icon + item.title;
		}
		
		return html;
	},
	
	isRealTime: function() {
		// return true if current page is in realtime mode, false otherwise
		var args = this.args;
		return (args.offset == 0 - args.length);
	},
	
	navCtrlBack: function() {
		// jump backward in time
		var args = this.args;
		args.offset -= args.length;
		this.navToArgs();
	},
	
	navCtrlForward: function() {
		// jump forward in time
		var args = this.args;
		if (!this.isRealTime()) {
			args.offset += args.length;
			this.navToArgs();
		}
	},
	
	applyMonitorFilter: function(initial) {
		// hide/show graphs based on current filter text
		if (!this.groups || !this.groups.length) return;
		var self = this;
		var filterMatch = new RegExp( escape_regexp(app.monitorFilter || '') || '.+', "i" );
		var changes = 0;
		var num_filtered = 0;
		var total_graphs = 0;
		
		this.groups.forEach( function(group_def) {
			var monitors = app.findMonitorsFromGroup( group_def );
			if (!monitors.length) return;
			
			monitors.forEach( function(mon_def, idx) {
				if (!mon_def.merge_type) return;
				var combo_id = group_def.id + '_' + mon_def.id;
				var visible = !!(mon_def.title.match(filterMatch) || mon_def.id.match(filterMatch));
				var $cont = self.div.find('#d_graph_ov_' + combo_id);
				
				if (visible && $cont.hasClass('filtered')) {
					$cont.removeClass('filtered').addClass('dirty');
					changes++;
				}
				else if (!visible && !$cont.hasClass('filtered')) {
					$cont.addClass('filtered');
					changes++;
				}
				if (!visible) num_filtered++;
				total_graphs++;
			}); // foreach monitor
		}); // foreach group
		
		if (changes && !initial) {
			this.onScrollDebounce();
		}
		
		if (num_filtered == total_graphs) {
			this.div.find('#fs_all_filtered').show();
		}
		else {
			this.div.find('#fs_all_filtered').hide();
		}
	},
	
	onThemeChange: function(theme) {
		// user has changed theme, update graphs
		if (this.graphs) {
			this.div.find('div.graph_container').addClass('dirty');
			this.onScrollDebounce();
		}
	},
	
	onDeactivate: function() {
		// called when page is deactivated
		if (this.graphs) {
			for (var key in this.graphs) {
				this.graphs[key].destroy();
			}
		}
		this.graphs = null;
		this.div.html( '' );
		return true;
	}
	
} );

Class.subclass( Page.Base, "Page.Group", {	
	
	onInit: function() {
		// called once at page load
		var html = '';
		this.div.html( html );
		this.initQueue();
	},
	
	onActivate: function(args) {
		// page activation
		var self = this;
		if (!this.requireLogin(args)) return true;
		
		if (!args) args = {};
		this.args = args;
		var renav = false;
		
		// default to hourly (which is also real-time)
		if (!args.sys) {
			args.sys = 'hourly';
			renav = true;
		}
		
		// if no group specified in args, default to first group in list
		if (!args.group && app.getPref('last_group_id')) {
			args.group = app.getPref('last_group_id');
			renav = true;
		}
		if (!args.group) {
			args.group = config.groups[0].id;
			renav = true;
		}
		app.setPref('last_group_id', args.group);
		
		if (!args.date && !args.length) {
			// default to realtime hourly
			args.offset = -60;
			args.length = 60;
			renav = true;
		}
		// date always needs to be treated as a string
		if (args.date) args.date = '' + args.date;
		
		if (renav) this.navReplaceArgs();
		
		// store group and monitors in page
		this.group = find_object( config.groups, { id: args.group } );
		if (!this.group) {
			return this.doInlineError("Group definition not found: " + args.group);
		}
		
		this.monitors = app.findMonitorsFromGroup( this.group );
		if (!this.monitors.length) {
			return this.doInlineError("No matching monitors for group: " + this.group.title);
		}
		
		app.setWindowTitle('Group Detail: ' + this.group.title);
		app.showTabBar(true);
		this.showControls(true);
		this.tab[0]._page_id = Nav.currentAnchor();
		
		// Realtime views:
		// #Group?group=main&sys=hourly&offset=-60&length=60
		// #Group?group=main&sys=hourly&offset=-180&length=180
		// #Group?group=main&sys=hourly&offset=-360&length=360
		// #Group?group=main&sys=hourly&offset=-720&length=720
		
		// Historical views:
		// #Group?group=main&sys=hourly&date=2019/02/23/12
		// #Group?group=main&sys=daily&date=2019/02/23
		// #Group?group=main&sys=monthly&date=2019/02
		// #Group?group=main&sys=yearly&date=2019
		
		this.rec_dead = {};
		this.graphs = null;
		
		if (this.div.is(':empty')) {
			this.div.addClass('loading');
		}
		
		this.requestData();
		return true;
	},
	
	requestData: function() {
		// request contributors (contrib) data for our group and range
		// this is for both real-time and historical views
		var self = this;
		var args = this.args;
		
		this.lastUpdate = time_now();
		
		app.api.get( 'app/contrib', args, function(data) {
			// {code: 0, hostnames: {joedark.local: 1, mini.local: 1}}
			
			if (!data.hostnames || !num_keys(data.hostnames)) {
				return self.doInlineError('No Data Found', 'No data was found for group "' + self.group.title + '", in the specified time range.');
			}
			
			// store hostnames in page
			self.hostnames = data.hostnames;
			
			// sort hosts
			self.hosts = hash_keys_to_array(self.hostnames).sort().map( function(hostname, idx) {
				return { hostname: hostname, idx: idx };
			});
			
			// now we can setup the graphs and request data samples
			self.setupGraphs();
			
			// if we're in real-time mode, merge hosts with recent and redraw jump menu
			if (self.isRealTime()) app.updateRecentHostnames( data.hostnames );
		}, 
		function(err) {
			if (err.code == "no_data") self.doInlineError( "No Data Found", "No data was found in the specified time range." );
			else self.doInlineError( "Server Error", err.description );
		} );
	},
	
	setupGraphs: function() {
		// render graph skeletons, assign layers, request data
		var self = this;
		var args = this.args;
		
		var html = '';
		// html += '<h1>' + this.group.title + '</h1>';
		html += '<div class="subtitle" style="margin-top:10px; margin-bottom:15px;">';
			html += '<i class="mdi mdi-server-network">&nbsp;</i>' + this.group.title + "";
			html += '<div class="subtitle_widget"><span class="link" onMouseUp="$P().editGroupWatch()"><i class="mdi mdi-eye mdi-lg">&nbsp;</i><b>Watch Group...</b></span></div>';
			html += '<div class="subtitle_widget"><span class="link" onMouseUp="$P().takeSnapshot()"><i class="fa fa-camera">&nbsp;</i><b>Take Snapshot</b></span></div>';
			html += '<div class="clear"></div>';
		html += '</div>';
		
		// insert alerts and server list table here
		// (will be populated later)
		html += '<fieldset id="fs_group_alerts" style="margin-top:10px; display:none"></fieldset>';
		html += '<fieldset id="fs_group_info" style="margin-top:10px; display:none"></fieldset>';
		
		// graph container
		html += '<div class="graphs group size_' + app.getPref('graph_size') + '" style="margin-top:10px;">';
		
		// graph placeholders
		this.monitors.forEach( function(mon_def) {
			html += '<div id="d_graph_group_' + mon_def.id + '" class="graph_container" data-mon="' + mon_def.id + '">';
			html += '<div class="graph_button copy"><i class="mdi mdi-clipboard-pulse-outline mdi-lg" title="Copy Graph Image URL" onMouseUp="$P().copyGraphImage(this)"></i></div>';
			
			var menu_opts = [ ['', "Multi-Line"], ['total', "Total"], ['avg', "Average"], ['min', "Minimum"], ['max', "Maximum"] ];
			html += '<div class="graph_button menu" title="Change Graph Type"><i class="mdi mdi-settings mdi-lg"></i>';
			html += '<select onChange="$P().changeMergeType(this)"><optgroup label="Graph Type">' + render_menu_options(menu_opts, app.getPref('ggt_' + mon_def.id)) + '</optgroup></select></div>';
			
			html += '<div id="c_graph_group_' + mon_def.id + '"></div>';
			html += '</div>';
		});
		
		html += '<div class="clear"></div>';
		html += '</div>';
		
		// for when all graphs are filtered out:
		html += '<fieldset class="inline_error" id="fs_all_filtered" style="display:none">';
		html += '<div class="inline_error_title">All Graphs Filtered</div>';
		html += '<div class="inline_error_msg">Please enter a different filter query.</div>';
		html += '</fieldset>';
		
		this.div.html(html);
		
		// create all graphs without data
		this.graphs = {};
		this.createGraphs();
		
		// calculate min/max for data bounds
		this.calcDataRange();
		
		// apply filters if any
		this.applyMonitorFilter(true);
		
		// fetch data from all servers in group simultaneously
		// the browser will throttle these to ~6 in parallel
		this.expecting = this.hosts.length;
		this.hosts.forEach( function(host) {
			var hostname = host.hostname;
			var server_args = copy_object(args);
			server_args.hostname = hostname;
			
			app.api.get( 'app/view', server_args, self.receiveData.bind(self), function(err) {
				// self.doInlineError( "API Error", err.description );
				// this is less of a page-destroying error in group view, so just log and move on
				Debug.trace('api', "API Error for " + hostname + ": " + err.description);
				
				self.expecting--;
				if (!self.expecting) {
					// welp, that was the final server we were waiting for, so trigger graph redraw now
					self.div.find('div.graph_container').addClass('dirty');
					self.onScrollDebounce();
					self.updateInfo();
					self.updateDataRangeDisplay();
				}
			} );
		});
	},
	
	createGraphs: function() {
		// create initial chart.js graphs (sans data, just layers)
		var self = this;
		
		// we have all the hostnames at this point, so might as well send in the legend labels
		var labels = this.hosts.map( function(host) {
			return self.formatHostname( host.hostname );
		});
		
		this.monitors.forEach( function(mon_def, idx) {
			var opts = null;
			var merge_type = app.getPref('ggt_' + mon_def.id);
			
			if (merge_type) {
				// merge multi-line into avg/min/max (per-graph user pref)
				opts = {
					id: mon_def.id,
					title: ucfirst(merge_type) + " " + mon_def.title,
					labels: [ ucfirst(merge_type.replace(/avg/, 'average')) ],
					color: self.graphColors[ idx % self.graphColors.length ],
					data_type: mon_def.data_type,
					suffix: mon_def.suffix || '',
					num_layers: 1,
					canvas_id: 'c_graph_group_' + mon_def.id,
					no_fill: false,
					show_legend: false
				};
			}
			else {
				// standard multi-line presentation
				opts = {
					id: mon_def.id,
					title: mon_def.title,
					labels: labels,
					data_type: mon_def.data_type,
					suffix: mon_def.suffix || '',
					num_layers: self.hosts.length,
					canvas_id: 'c_graph_group_' + mon_def.id,
					no_fill: true, // force line graphs, even if only 1 server in group
					show_legend: true // always show legend in group view
				};
			}
			
			self.graphs[mon_def.id] = self.createGraph(opts);
		});
	},
	
	calcDataRange: function() {
		// calculate min/max for data bounds
		var args = this.args;
		var range_min = 0;
		var range_max = 0;
		
		if (this.isRealTime()) {
			range_min = (time_now() + (args.offset * 60)) * 1000;
			range_max = (time_now() + (args.offset * 60) + (args.length * 60)) * 1000;
		}
		
		// save these for later
		this.range_min = range_min;
		this.range_max = range_max;
	},
	
	isRowInRange: function(row) {
		// calculate if row.date is within our range bounds
		if (this.range_min && (row.date < this.range_min / 1000)) return false;
		if (this.range_max && (row.date > this.range_max / 1000)) return false;
		return true;
	},
	
	updateDataRangeDisplay: function() {
		// scan current dataset for min/max epoch and render data range in control strip
		var self = this;
		var min_date = 0;
		var max_date = 0;
		
		if (!this.isRealTime()) return;
		
		this.hosts.forEach( function(host) {
			if (!host.rows) return;
			host.rows.forEach( function(row) {
				if (self.isRowInRange(row)) {
					if (!min_date || (row.date < min_date)) min_date = row.date;
					if (!max_date || (row.date > max_date)) max_date = row.date;
				}
			}); // foreach row
		}); // foreach host
		
		// display data range
		this.displayDataRange( min_date, max_date );
	},
	
	receiveData: function(data) {
		// receive view data from one single server in group
		// data: { code, hostname, rows, metadata }
		var self = this;
		var args = this.args;
		this.div.removeClass('loading');
		
		// find matching host object so we can store stuff in it
		var host = find_object( this.hosts, { hostname: data.hostname } );
		if (!host) return app.doError("Hostname not found: " + data.hostname); // should never happen
		
		host.rows = data.rows;
		host.metadata = data.metadata;
		
		if (!host.rows.length) {
			Debug.trace('api', 'No data was found for server "' + data.hostname + '", in the specified time range.');
		}
		
		// data comes in as totals (may be more than one sample per timestamp), so pre-average everything
		host.rows.forEach( function(row) {
			for (var key in row.totals) {
				row.totals[key] /= row.count || 1;
			}
		});
		
		// trigger visible graph redraw (also happens on debounced scroll)
		// only if all hosts have reported in (reduce number of graph draws)
		this.expecting--;
		if (!this.expecting) {
			this.div.find('div.graph_container').addClass('dirty');
			this.onScrollDebounce();
			this.updateInfo();
			this.updateDataRangeDisplay();
		}
	},
	
	updateGraph: function(mon_id) {
		// update single graph
		// called on dequeue
		var self = this;
		var graph = this.graphs[mon_id];
		var series = [];
		var alert_times = [];
		var min_date = time_now();
		
		// see if graph is still visible (queue delay -- user could have scrolled past)
		if (!this.div.find('#d_graph_group_' + mon_id).visible(true, true)) {
			this.div.find('#d_graph_group_' + mon_id).addClass('dirty');
			return;
		}
		
		// pre-scan alert defs for monitor_id (for optimization in inner loop below)
		var active_alerts = {};
		config.alerts.forEach( function(alert_def) {
			if (alert_def.monitor_id == mon_id) active_alerts[ alert_def.id ] = true;
		});
		
		var sys_def = find_object( config.systems, { id: this.args.sys } ) || { epoch_div: 9999999 };
		
		this.hosts.forEach( function(host) {
			// build datasets for each host (layer)
			var graph_rows = [];
			var last_row = null;
			
			if (host.rows) host.rows.forEach( function(row) {
				if ((mon_id in row.totals) && self.isRowInRange(row)) {
					// handle gaps
					if (last_row && (row.date - last_row.date > sys_def.epoch_div * 2)) {
						// insert null gap
						graph_rows.push({ x: (last_row.date * 1000) + 1, y: null });
					}
					
					graph_rows.push({ x: row.date * 1000, y: row.totals[mon_id] });
					
					if (row.date < min_date) min_date = row.date;
					
					if (row.alerts) {
						var yes_alert = false;
						
						for (var alert_id in row.alerts) {
							if (active_alerts[alert_id]) { yes_alert = true; break; }
						} // foreach alert
						
						if (yes_alert) alert_times.push( row.date * 1000 );
					} // alerts
					
					last_row = row;
				} // in range
			}); // foreach row
			
			series.push({
				name: self.formatHostname( host.hostname ),
				data: self.crushData( graph_rows )
			});
		}); // foreach host
		
		// possibly merge all series into single dataset (min/avg/max/total)
		if (app.getPref('ggt_' + mon_id)) {
			series = this.mergeMultiSeries( mon_id, series );
		}
		
		// setup annotations
		var x_annos = [];
		if (app.getPref('annotations') == '1') {
			alert_times.forEach( function(x) {
				x_annos.push({
					x: x,
					borderColor: '#888',
					yAxisIndex: 0,
					label: {
						show: true,
						text: 'Alert',
						style: {
							color: "#fff",
							background: '#f00'
						}
					}
				});
			});
			
			if (this.isRealTime()) {
				// allow a few minutes of slack here, just in case a server had a hiccup
				var min_x = (min_date + 180) * 1000;
				
				series.forEach( function(item, idx) {
					var rows = item.data;
					if (rows.length && (rows[0].x > min_x)) {
						x_annos.push({
							x: rows[0].x,
							borderColor: '#888',
							yAxisIndex: 0,
							label: {
								show: true,
								text: 'New',
								style: {
									color: "#fff",
									// background: '#080'
									background: self.graphColors[ idx % self.graphColors.length ]
								}
							}
						}); // x_annos.push
					} // new host
				} ); // foreach series
			} // real-time
		} // annotations enabled
		
		// redraw graph series and annos
		var options = this.getGraphConfig(mon_id);
		options.series = series;
		options.annotations = {
			xaxis: x_annos
		};
		graph.updateOptions(options, true, false);
	},
	
	onScrollDebounce: function(instant) {
		// called for redraw, and for scroll (debounced)
		// find all graphs which are dirty AND visible, and update them
		var self = this;
		
		this.div.find('div.graph_container.dirty').each( function() {
			var $this = $(this);
			if (!$this.hasClass('filtered') && $this.visible(true, true)) {
				var mon_id = $this.data('mon');
				Debug.trace('graph', "Rendering graph for scroll event: " + mon_id);
				$this.removeClass('dirty');
				
				// reset copy icon, just in case
				$this.find('div.graph_button.copy > i').removeClass().addClass('mdi mdi-clipboard-pulse-outline mdi-lg');
				
				if (instant) self.updateGraph(mon_id);
				else self.enqueue( self.updateGraph.bind(self, mon_id), mon_id );
			}
		});
	},
	
	updateGroupData: function(overrides) {
		// update entire group for 30s refresh, or focus refresh
		// overrides can reset any page args, like setting offset/length to -1/1
		// (this is ONLY called for real-time views)
		var self = this;
		var args = this.args;
		if (!overrides) overrides = {};
		
		// special case: if we are in an error state, perform a full refresh
		if (!this.graphs) return this.requestData();
		
		Debug.trace("Requesting group data update");
		this.lastUpdate = time_now();
		
		// recalculate this, as time moves ever forward
		this.calcDataRange();
		
		// first, we need to see if contrib has changed (new servers may have joined the group)
		var contrib_args = merge_objects(args, overrides);
		
		app.api.get( 'app/contrib', contrib_args, function(data) {
			// {code: 0, hostnames: {joedark.local: 1, mini.local: 1}}
			
			if (!data.hostnames || !num_keys(data.hostnames)) {
				Debug.trace('api', 'No data was found for group "' + self.group.id + '", in the specified time range.');
				return;
			}
			
			// any new hostnames?  If so, they need to be assigned entries in hosts array, 
			// and new graphs created
			var new_hostnames = [];
			for (var hostname in data.hostnames) {
				if (!(hostname in self.hostnames)) new_hostnames.push(hostname);
			}
			
			var dead_hostnames = [];
			for (var hostname in self.hostnames) {
				if (!(hostname in data.hostnames)) {
					// only drop host if data is stale
					var host = find_object( self.hosts, { hostname: hostname } );
					if (!host || !host.rows || !host.rows.length || (host.rows[ host.rows.length - 1 ].date < self.range_min / 1000)) {
						dead_hostnames.push( hostname );
					}
				}
			}
			
			if (dead_hostnames.length) {
				dead_hostnames.forEach( function(hostname) {
					Debug.trace("Removing dead host from group: " + hostname);
					
					var host_idx = find_object_idx( self.hosts, { hostname: hostname } );
					if (host_idx > -1) {
						self.hosts.splice( host_idx, 1 );
						delete self.hostnames[hostname];
						delete app.recent_hostnames[hostname];
					}
					
					// save death time in RAM cache to prevent reappearance
					// (this can happen on focus refresh, because contrib data lags behind a bit)
					self.rec_dead[hostname] = time_now();
				});
				
				// renumber remaining hosts to remove any idx gaps
				self.hosts.forEach( function(host, idx) {
					host.idx = idx;
				});
			} // dead removed
			
			if (new_hostnames.length) {
				new_hostnames.forEach( function(hostname) {
					if (self.rec_dead[hostname] && ((time_now() - self.rec_dead[hostname]) < 3600)) {
						// skip adding this host again, until it has been dead for 1+ hr
						return;
					}
					
					Debug.trace("Adding new host to group: " + hostname);
					
					var new_idx = self.hosts.length;
					self.hosts.push({ hostname: hostname, idx: new_idx });
					self.hostnames[hostname] = data.hostnames[hostname];
					app.recent_hostnames[hostname] = data.hostnames[hostname];
				}); // foreach new hostname
			} // new added
			
			if (new_hostnames.length || dead_hostnames.length) {
				// rebuild "jump to server" menu with new hosts
				app.initJumpMenus();
				
				// destroy and recreate all graphs as quickly as possible
				for (var key in self.graphs) {
					self.graphs[key].destroy();
				}
				self.createGraphs();
				
				self.div.find('div.graph_container').addClass('dirty');
				self.onScrollDebounce(true); // instant (bypass queue)
			} // new hosts added
			
			// now fetch data updates from all servers in parallel
			self.expecting = self.hosts.length;
			self.hosts.forEach( function(host) {
				var hostname = host.hostname;
				var server_args = merge_objects(args, overrides);
				server_args.hostname = hostname;
				
				app.api.get( 'app/view', server_args, self.receiveUpdate.bind(self), function(err) {
					Debug.trace('api', "API Error for " + hostname + ": " + err.description);
					
					self.expecting--;
					if (!self.expecting) {
						// welp, that was the final server we were waiting for, so trigger graph redraw now
						self.div.find('div.graph_container').addClass('dirty');
						self.onScrollDebounce();
						self.updateInfo();
						self.updateDataRangeDisplay();
					}
				} );
			});
			
			// merge hosts with recent and redraw jump menu
			app.updateRecentHostnames( data.hostnames );
		}, 
		function(err) {
			self.doInlineError( "Server Error", err.description );
		} );
	},
	
	onSecond30: function(dargs) {
		// update graphs on the :30s, but only in realtime view
		var args = this.args;
		
		/*if (this.isRealTime() && (app.getPref('auto_refresh') == '1')) {
			this.updateGroupData({ offset: -2, length: 2 });
		}*/
		this.onFocus();
	},
	
	onFocus: function() {
		// window received focus, update data
		var args = this.args;
		
		if (this.isRealTime() && (app.getPref('auto_refresh') == '1') && this.lastUpdate) {
			// only request the data we actually need
			var now = time_now();
			var minutes_lost = Math.floor((now - this.lastUpdate) / 60) + 1;
			if (minutes_lost < args.length) this.updateGroupData({ offset: 0 - minutes_lost, length: minutes_lost });
			else this.updateGroupData();
		}
	},
	
	receiveUpdate: function(data) {
		// receive update from server
		// data: { code, hostname, rows, metadata }
		var self = this;
		var rows = data.rows;
		var metadata = data.metadata;
		var args = this.args;
		
		if (!rows.length) {
			Debug.trace("No rows found in update: " + data.hostname);
		}
		
		// find matching host object so we can store stuff in it
		var host = find_object( this.hosts, { hostname: data.hostname } );
		if (!host) return app.doError("Hostname not found: " + data.hostname); // should never happen
		if (!host.rows) host.rows = [];
		host.metadata = data.metadata;
		
		// skip dupes
		var new_rows = [];
		rows.forEach( function(row) {
			if (!find_object(host.rows, { date: row.date })) new_rows.push(row);
		});
		rows = new_rows;
		
		if (!rows.length) {
			Debug.trace("All rows were dupes in update: " + data.hostname);
		}
		else {
			// data comes in as totals (may be more than one sample per timestamp), so pre-average everything
			rows.forEach( function(row) {
				for (var key in row.totals) {
					row.totals[key] /= row.count || 1;
				}
				host.rows.push( row );
			});
			
			// sort just in case
			host.rows = host.rows.sort( function(a, b) {
				return (a.date - b.date);
			});
			
			// discard old if beyond length
			while (host.rows.length > args.length) host.rows.shift();
		}
		
		// trigger visible graph redraw (also happens on debounced scroll)
		// only if all servers have reported in
		self.expecting--;
		if (!self.expecting) {
			// welp, that was the final server we were waiting for, so trigger graph redraw now
			self.div.find('div.graph_container').addClass('dirty');
			self.onScrollDebounce();
			self.updateInfo();
			self.updateDataRangeDisplay();
		}
	},
	
	getNiceHostname: function(hostname, idx) {
		// get formatted hostname with icon, plus optional link
		var width = 500;
		var link = true;
		var color = this.graphColors[ idx % this.graphColors.length ];
		if (!hostname) return '(None)';
		
		var query = { hostname: hostname };
		if (this.args && this.args.sys) query.sys = this.args.sys;
		if (this.args && this.args.date) query.date = this.args.date;
		if (this.args && ('offset' in this.args)) query.offset = this.args.offset;
		if (this.args && this.args.length) query.length = this.args.length;
		
		var html = '<div class="ellip" style="max-width:' + width + 'px;">';
		var icon = '<i class="mdi mdi-circle" style="color:' + color + '">&nbsp;</i>';
		if (link) {
			html += '<a href="#Server' + compose_query_string(query) + '" style="text-decoration:none">';
			html += icon + '<span style="text-decoration:underline">' + this.formatHostname(hostname) + '</span></a>';
		}
		else {
			html += icon + this.formatHostname(hostname);
		}
		html += '</div>';
		
		return html;
	},
	
	updateInfo: function() {
		// update group alerts and info
		var self = this;
		
		// gather alerts in realtime mode
		var all_alerts = [];
		this.hosts.forEach( function(host) {
			var metadata = host.metadata || {};
			if (metadata.alerts) {
				for (var alert_id in metadata.alerts) {
					all_alerts.push( 
						merge_objects( metadata.alerts[alert_id], { 
							id: alert_id, 
							hostname: host.hostname 
						} )
					);
				} // foreach alert
			} // has alerts
		}); // foreach host
		
		if (all_alerts.length && this.isRealTime()) {
			// build alert table
			var html = '';
			html += '<legend style="color:red">Current Alerts</legend>';
			html += '<table class="fieldset_table" width="100%">';
			html += '<tr>';
				html += '<th>Alert</th>';
				html += '<th>Hostname</th>';
				html += '<th>Detail</th>';
				html += '<th>Trigger</th>';
				html += '<th>Date/Time</th>';
				html += '<th>Actions</th>';
			html += '</tr>';
			
			all_alerts.forEach( function(alert) {
				var alert_def = find_object( config.alerts, { id: alert.id } ) || { 
					id: alert.id,
					title: '(' + alert.id + ')',
					expression: 'n/a'
				};
				var host = find_object( self.hosts, { hostname: alert.hostname } ) || { idx: 0 };
				html += '<tr>';
				html += '<td><b>' + self.getNiceAlert(alert_def, true) + '</b></td>';
				html += '<td>' + self.getNiceHostname(alert.hostname, host.idx) + '</td>';
				html += '<td>' + alert.message + '</td>';
				html += '<td style="font-family:monospace">' + alert_def.expression + '</pre></td>';
				html += '<td>' + get_nice_date_time( alert.date ) + '</td>';
				
				var snap_id = alert.hostname + '/' + Math.floor( alert.date / 60 );
				html += '<td><a href="#Snapshot?id=' + snap_id + '">View&nbsp;Snapshot</a></td>';
				
				html += '</tr>';
			});
			
			html += '</table>';
			this.div.find('#fs_group_alerts').empty().html(html).show();
		}
		else {
			// no alerts, hide entire fieldset
			this.div.find('#fs_group_alerts').empty().hide();
		}
		
		// any filter at all hides info fieldset
		if (app.monitorFilter) {
			this.div.find('#fs_group_info').empty().hide();
			return;
		}
		
		// group info table: fs_group_info
		var extra_server_info = config.extra_server_info;
		var html = '';
		// html += '<legend>' + this.group.title +'</legend>';
		html += '<legend>Group Members</legend>';
		html += '<table class="fieldset_table" width="100%">';
		html += '<tr>';
			html += '<th>Hostname</th>';
			html += '<th>IP Address</th>';
			// html += '<th>Load Avg</th>';
			html += '<th>CPUs</th>';
			html += '<th>Total RAM</th>';
			html += '<th>Operating System</th>';
			html += '<th>' + extra_server_info.title + '</th>';
			html += '<th>Uptime</th>';
			// html += '<th>Alerts</th>';
		html += '</tr>';
		
		this.hosts.forEach( function(host) {
			var metadata = host.metadata || { data: { memory: {}, os: {} } };
			var nice_os = 'n/a';
			if (metadata.data.os.distro) {
				nice_os = metadata.data.os.distro + ' ' + metadata.data.os.release; //  + ' (' + metadata.data.os.arch + ')';
			}
			var nice_kernel = 'n/a';
			if (extra_server_info.source) {
				nice_kernel = substitute(extra_server_info.source, metadata.data, false);
			}
			var is_stale = false;
			if (self.isRealTime() && host.rows && host.rows.length) {
				var row = host.rows[ host.rows.length - 1 ];
				if (row.date < time_now() - 600) is_stale = true;
			}
			
			html += '<tr ' + (is_stale ? 'class="disabled"' : '') + '>';
			html += '<td><b>' + self.getNiceHostname(host.hostname, host.idx) + '</b></td>';
			html += '<td>' + (metadata.ip || 'n/a') + '</td>';
			html += '<td>' + (metadata.data.cpu ? metadata.data.cpu.cores : 0) + '</td>';
			html += '<td>' + get_text_from_bytes(metadata.data.memory.total || 0) + '</td>';
			html += '<td>' + nice_os + '</td>';
			html += '<td>' + nice_kernel + '</td>';
			html += '<td>' + get_text_from_seconds(metadata.data.uptime_sec || 0, false, true) + '</td>';
			html += '</tr>';
		});
		
		this.div.find('#fs_group_info').empty().html(html).show();
	},
	
	mergeMultiSeries: function(mon_id, series) {
		// merge multi-series into single using min/max/avg/total
		var mon_def = find_object( this.monitors, { id: mon_id } );
		var merge_type = app.getPref('ggt_' + mon_id);
		var time_index = {};
		
		series.forEach( function(dataset) {
			dataset.data.forEach( function(row) {
				if (!time_index[row.x]) {
					time_index[row.x] = { 
						x: row.x,
						total: row.y, 
						count: 1, 
						min: row.y, 
						max: row.y
					};
				}
				else {
					time_index[row.x].total += row.y;
					time_index[row.x].count++;
					if (row.y < time_index[row.x].min) time_index[row.x].min = row.y;
					if (row.y > time_index[row.x].max) time_index[row.x].max = row.y;
				}
			} );
		} );
		
		var rows = [];
		var sorted_times = hash_keys_to_array(time_index).sort( function(a, b) {
			return parseInt(a) - parseInt(b);
		});
		
		sorted_times.forEach( function(key) {
			var row = time_index[key];
			switch (merge_type) {
				case 'avg': 
					var avg = row.total / row.count;
					if (mon_def.data_type.match(/(integer|bytes|seconds|milliseconds)/)) avg = Math.floor(avg);
					rows.push({ x: row.x, y: avg }); 
				break;
				case 'total': rows.push({ x: row.x, y: row.total }); break;
				case 'min': rows.push({ x: row.x, y: row.min }); break;
				case 'max': rows.push({ x: row.x, y: row.max }); break;
			}
		});
		
		return [{
			name: ucfirst( merge_type.replace(/avg/, 'average') ),
			data: rows
		}];
	},
	
	changeMergeType: function(elem) {
		// change graph merge type (from menu click)
		var self = this;
		var $elem = $(elem);
		var args = this.args;
		var $cont = $elem.closest('div.graph_container');
		var mon_id = $cont.data('mon');
		var mon_def = find_object( this.monitors, { id: mon_id } );
		var mon_idx = find_object_idx( this.monitors, { id: mon_id } );
		var graph = this.graphs[mon_id];
		
		var merge_type = $elem.val();
		app.setPref('ggt_' + mon_id, merge_type);
		
		// update settings
		var settings = this.graphSettings[mon_id];
		if (merge_type) {
			// convert to merge (single layer)
			settings.title = ucfirst(merge_type) + " " + mon_def.title;
			settings.labels = [ ucfirst(merge_type.replace(/avg/, 'average')) ];
			settings.color = this.graphColors[ mon_idx % this.graphColors.length ];
			settings.num_layers = 1;
			settings.no_fill = false;
			settings.show_legend = false;
		}
		else {
			// convert back to multi-line
			settings.title = mon_def.title;
			settings.labels = [];
			delete settings.color;
			settings.num_layers = this.hosts.length;
			settings.no_fill = true;
			settings.show_legend = true;
		}
		
		// redraw graph
		graph.destroy();
		this.graphs[mon_id] = this.createGraph(settings);
		this.updateGraph(mon_id);
	},
	
	applyMonitorFilter: function(initial) {
		// hide/show graphs based on current filter text
		if (!this.monitors || !this.monitors.length) return;
		var self = this;
		var filterMatch = new RegExp( escape_regexp(app.monitorFilter || '') || '.+', "i" );
		var changes = 0;
		var num_filtered = 0;
		
		this.monitors.forEach( function(mon_def, idx) {
			var visible = !!(mon_def.title.match(filterMatch) || mon_def.id.match(filterMatch));
			var $cont = self.div.find('#d_graph_group_' + mon_def.id);
			
			if (visible && $cont.hasClass('filtered')) {
				$cont.removeClass('filtered').addClass('dirty');
				changes++;
			}
			else if (!visible && !$cont.hasClass('filtered')) {
				$cont.addClass('filtered');
				changes++;
			}
			if (!visible) num_filtered++;
		});
		
		if (changes && !initial) {
			this.onScrollDebounce();
		}
		if (!initial) {
			this.updateInfo();
		}
		if (num_filtered == this.monitors.length) {
			this.div.find('#fs_all_filtered').show();
		}
		else {
			this.div.find('#fs_all_filtered').hide();
		}
	},
	
	editGroupWatch: function() {
		// open group watch dialog
		var self = this;
		var args = this.args;
		var html = '';
		var watch_sel = 0;
		var state = config.state;
		var hostnames = this.hosts.map( function(host) { return host.hostname; } );
		
		var watch_items = [
			[0, "(Disable Watch)"],
			app.getTimeMenuItem( 60 ),
			app.getTimeMenuItem( 60 * 5 ),
			app.getTimeMenuItem( 60 * 10 ),
			app.getTimeMenuItem( 60 * 15 ),
			app.getTimeMenuItem( 60 * 30 ),
			app.getTimeMenuItem( 60 * 45 ),
			app.getTimeMenuItem( 3600 ),
			app.getTimeMenuItem( 3600 * 2 ),
			app.getTimeMenuItem( 3600 * 3 ),
			app.getTimeMenuItem( 3600 * 6 ),
			app.getTimeMenuItem( 3600 * 12 ),
			app.getTimeMenuItem( 86400 ),
			app.getTimeMenuItem( 86400 * 2 ),
			app.getTimeMenuItem( 86400 * 3 ),
			app.getTimeMenuItem( 86400 * 7 ),
			app.getTimeMenuItem( 86400 * 15 ),
			app.getTimeMenuItem( 86400 * 30 )
		];
		
		html += '<div style="font-size:12px; margin-bottom:20px;">Use the menu below to optionally set watch timers <b>on all current servers in the group</b>.  This will generate snapshots every minute until the timer expires.</div>';
		watch_sel = 3600;
		
		html += '<center><table>' + 
			// get_form_table_spacer() + 
			get_form_table_row('Watch For:', '<select id="fe_watch_time">' + render_menu_options(watch_items, watch_sel) + '</select>') + 
			get_form_table_caption("Select the duration for the group watch.") + 
		'</table></center>';
		
		app.confirm( '<i class="mdi mdi-eye">&nbsp;</i>Watch Group', html, "Set Watch", function(result) {
			app.clearError();
			
			if (result) {
				var watch_time = parseInt( $('#fe_watch_time').val() );
				var watch_date = time_now() + watch_time;
				Dialog.hide();
				
				app.api.post( 'app/watch', { hostnames: hostnames, date: watch_date }, function(resp) {
					// update local state and show message
					if (!state.watches) state.watches = {};
					
					if (watch_time) {
						app.showMessage('success', "Group will be watched for " + get_text_from_seconds(watch_time, false, true) + ".");
						hostnames.forEach( function(hostname) {
							state.watches[ hostname ] = watch_date;
						});
					}
					else {
						app.showMessage('success', "Group watch has been disabled.");
						hostnames.forEach( function(hostname) {
							delete state.watches[ hostname ];
						});
					}
					
				} ); // api.post
			} // user clicked set
		} ); // app.confirm
	},
	
	takeSnapshot: function() {
		// take a snapshot (i.e. 1 minute watch)
		var self = this;
		var args = this.args;
		var state = config.state;
		var watch_time = 60;
		var watch_date = time_now() + watch_time;
		// var hostnames = this.hosts.map( function(host) { return host.hostname; } );
		
		var hostnames = [];
		this.hosts.forEach( function(host) {
			var is_stale = false;
			if (self.isRealTime() && host.rows && host.rows.length) {
				var row = host.rows[ host.rows.length - 1 ];
				if (row.date < time_now() - 600) is_stale = true;
			}
			if (!is_stale) hostnames.push( host.hostname );
		});
		if (!hostnames.length) return app.doError("Snapshots are not possible, as all servers in the group have gone stale (offline).");
		
		app.api.post( 'app/watch', { hostnames: hostnames, date: watch_date }, function(resp) {
			// update local state and show message
			if (!state.watches) state.watches = {};
			app.showMessage('success', 'Your snapshot(s) will be taken within a minute, and appear on the <a href="#Snapshot">Snapshots</a> tab.');
			hostnames.forEach( function(hostname) {
				state.watches[ hostname ] = watch_date;
			});
		} ); // api.post
	},
	
	onThemeChange: function(theme) {
		// user has changed theme, update graphs
		if (this.graphs) {
			this.div.find('div.graph_container').addClass('dirty');
			this.onScrollDebounce();
		}
	},
	
	onDeactivate: function() {
		// called when page is deactivated
		if (this.graphs) {
			for (var key in this.graphs) {
				this.graphs[key].destroy();
			}
		}
		this.queue = [];
		if (this.queueTimer) clearTimeout( this.queueTimer );
		this.hostnames = null;
		this.hosts = null;
		this.graphs = null;
		this.rec_dead = null;
		this.div.html( '' );
		return true;
	}
	
} );

Class.subclass( Page.Base, "Page.Server", {	
	
	onInit: function() {
		// called once at page load
		var html = '';
		this.div.html( html );
		this.initQueue();
	},
	
	onActivate: function(args) {
		// page activation
		var self = this;
		if (!this.requireLogin(args)) return true;
		
		if (!args) args = {};
		this.args = args;
		var renav = false;
		
		// default to hourly (which is also used for real-time)
		if (!args.sys) {
			args.sys = 'hourly';
			renav = true;
		}
		
		// if no server specified in args, default to first server in recent contrib list
		if (!args.hostname && app.getPref('last_hostname')) {
			args.hostname = app.getPref('last_hostname');
			renav = true;
		}
		if (!args.hostname) {
			args.hostname = hash_keys_to_array(app.recent_hostnames).sort().shift();
			renav = true;
		}
		if (!args.hostname) {
			this.doInlineError('No Servers Found', 'No servers have submitted any monitoring data yet.');
			return true;
		}
		app.setPref('last_hostname', args.hostname);
		
		if (!args.date && !args.length) {
			// default to realtime hourly
			args.offset = -60;
			args.length = 60;
			renav = true;
		}
		// date always needs to be treated as a string
		if (args.date) args.date = '' + args.date;
		
		if (renav) this.navReplaceArgs();
		
		app.setWindowTitle('Server Detail: ' + args.hostname);
		app.showTabBar(true);
		this.showControls(true);
		this.tab[0]._page_id = Nav.currentAnchor();
		
		// Realtime views:
		// #Server?hostname=foo.com&sys=hourly&offset=-60&length=60
		// #Server?hostname=foo.com&sys=hourly&offset=-180&length=180
		// #Server?hostname=foo.com&sys=hourly&offset=-360&length=360
		// #Server?hostname=foo.com&sys=hourly&offset=-720&length=720
		
		// Historical views:
		// #Server?hostname=foo.com&sys=hourly&date=2019/02/23/12
		// #Server?hostname=foo.com&sys=daily&date=2019/02/23
		// #Server?hostname=foo.com&sys=monthly&date=2019/02
		// #Server?hostname=foo.com&sys=yearly&date=2019
		
		this.graphs = null;
		
		if (this.div.is(':empty')) {
			this.div.addClass('loading');
		}
		
		this.requestData();
		return true;
	},
	
	requestData: function() {
		// request server data and metadata for this view
		var self = this;
		var args = this.args;
		
		app.api.get( 'app/view/verbose', args, this.receiveData.bind(this), function(err) {
			if (err.code == "no_data") self.doInlineError( "No Data Found", "No data was found in the specified time range." );
			else self.doInlineError( "Server Error", err.description );
		} );
	},
	
	receiveData: function(data) {
		// receive view data from server
		// data: { code, hostname, rows, metadata }
		var self = this;
		var args = this.args;
		this.div.removeClass('loading');
		this.rows = data.rows;
		this.metadata = data.metadata;
		
		if (!this.rows.length || !this.metadata) {
			return this.doInlineError('No Data Found', 'No data was found for server "' + this.args.hostname + '", in the specified time range.');
		}
		
		this.group = app.findGroupFromHostData( this.metadata );
		if (!this.group) {
			return this.doInlineError("No matching group found for server: " + this.args.hostname);
		}
		
		this.monitors = app.findMonitorsFromGroup( this.group );
		if (!this.monitors.length) {
			return this.doInlineError("No matching monitors for group: " + this.group.title);
		}
		
		// data comes in as totals (may be more than one sample per timestamp), so pre-average everything
		this.rows.forEach( function(row) {
			for (var key in row.totals) {
				row.totals[key] /= row.count || 1;
			}
		});
		
		var html = '';
		// html += '<h1>' + app.formatHostname(args.hostname) + '</h1>';
		html += '<div class="subtitle" style="margin-top:10px; margin-bottom:15px;">';
			html += '<i class="mdi mdi-desktop-tower">&nbsp;</i>' + app.formatHostname(args.hostname) + "";
			html += '<div class="subtitle_widget"><span class="link" onMouseUp="$P().editServerWatch()"><i class="mdi mdi-eye mdi-lg">&nbsp;</i><b>Watch Server...</b></span></div>';
			html += '<div class="subtitle_widget"><span class="link" onMouseUp="$P().takeSnapshot()"><i class="fa fa-camera">&nbsp;</i><b>Take Snapshot</b></span></div>';
			html += '<div class="clear"></div>';
		html += '</div>';
		
		// insert alerts and server info here
		// (will be populated later)
		html += '<fieldset id="fs_server_alerts" style="margin-top:10px; display:none"></fieldset>';
		html += '<fieldset id="fs_server_info" style="margin-top:10px; display:none"></fieldset>';
		html += '<fieldset id="fs_server_cpus" style="margin-top:10px; display:none"></fieldset>';
		
		html += '<div class="graphs server size_' + app.getPref('graph_size') + '" style="margin-top:10px;">';
		
		// graph placeholders
		this.monitors.forEach( function(mon_def) {
			html += '<div id="d_graph_server_' + mon_def.id + '" class="graph_container" data-mon="' + mon_def.id + '">';
			html += '<div class="graph_button copy"><i class="mdi mdi-clipboard-pulse-outline mdi-lg" title="Copy Graph Image URL" onMouseUp="$P().copyGraphImage(this)"></i></div>';
			html += '<div id="c_graph_server_' + mon_def.id + '"></div>';
			html += '</div>';
		});
		
		html += '<div class="clear"></div>';
		html += '</div>';
		
		// for when all graphs are filtered out:
		html += '<fieldset class="inline_error" id="fs_all_filtered" style="display:none">';
		html += '<div class="inline_error_title">All Graphs Filtered</div>';
		html += '<div class="inline_error_msg">Please enter a different filter query.</div>';
		html += '</fieldset>';
		
		this.div.html(html);
		
		// create all graphs without data
		this.graphs = {};
		
		this.monitors.forEach( function(mon_def, idx) {
			self.graphs[mon_def.id] = self.createGraph({
				id: mon_def.id,
				title: mon_def.title,
				data_type: mon_def.data_type,
				suffix: mon_def.suffix || '',
				num_layers: 1,
				canvas_id: 'c_graph_server_' + mon_def.id,
				color: self.graphColors[ idx % self.graphColors.length ]
			});
		});
		
		// calculate min/max for data bounds
		this.calcDataRange();
		
		// update and render data range display in control strip
		this.updateDataRangeDisplay();
		
		// apply filters if any
		this.applyMonitorFilter(true);
		
		// trigger visible graph redraw (also happens on debounced scroll)
		this.div.find('div.graph_container').addClass('dirty');
		this.onScrollDebounce();
		this.updateInfo();
		
		// show warning if server data is stale (only in real-time mode)
		if (this.isRealTime() && this.rows && this.rows.length) {
			var row = this.rows[ this.rows.length - 1 ];
			if (row.date < time_now() - 600) {
				app.showMessage( 'warning', "This server has not submitted any data in over 10 minutes.  It may have gone offline." );
			}
		}
	},
	
	calcDataRange: function() {
		// calculate min/max for data bounds
		var args = this.args;
		var range_min = 0;
		var range_max = 0;
		
		if (this.isRealTime()) {
			range_min = (time_now() + (args.offset * 60)) * 1000;
			range_max = (time_now() + (args.offset * 60) + (args.length * 60)) * 1000;
		}
		
		// save these for later
		this.range_min = range_min;
		this.range_max = range_max;
	},
	
	isRowInRange: function(row) {
		// calculate if row.date is within our range bounds
		if (this.range_min && (row.date < this.range_min / 1000)) return false;
		if (this.range_max && (row.date > this.range_max / 1000)) return false;
		return true;
	},
	
	updateDataRangeDisplay: function() {
		// scan current dataset for min/max epoch and render data range in control strip
		var self = this;
		var min_date = 0;
		var max_date = 0;
		
		if (!this.isRealTime()) return;
		
		this.rows.forEach( function(row) {
			if (self.isRowInRange(row)) {
				if (!min_date || (row.date < min_date)) min_date = row.date;
				if (!max_date || (row.date > max_date)) max_date = row.date;
			}
		});
		
		// display data range
		this.displayDataRange( min_date, max_date );
	},
	
	updateGraph: function(mon_id) {
		// update single graph
		// called on dequeue
		var self = this;
		var graph = this.graphs[mon_id];
		var graph_rows = [];
		var alert_times = [];
		
		// see if graph is still visible (queue delay -- user could have scrolled past)
		if (!this.div.find('#d_graph_server_' + mon_id).visible(true, true)) {
			this.div.find('#d_graph_server_' + mon_id).addClass('dirty');
			return;
		}
		
		// pre-scan alerts for monitor_id for optimization
		var active_alerts = {};
		config.alerts.forEach( function(alert_def) {
			if (alert_def.monitor_id == mon_id) active_alerts[ alert_def.id ] = true;
		});
		
		// process each row
		var last_row = null;
		var sys_def = find_object( config.systems, { id: this.args.sys } ) || { epoch_div: 9999999 };
		
		this.rows.forEach( function(row) {
			if ((mon_id in row.totals) && self.isRowInRange(row)) {
				// handle gaps
				if (last_row && (row.date - last_row.date > sys_def.epoch_div * 2)) {
					// insert null gap
					graph_rows.push({ x: (last_row.date * 1000) + 1, y: null });
				}
				
				graph_rows.push({ x: row.date * 1000, y: row.totals[mon_id] });
				
				if (row.alerts) {
					var yes_alert = false;
					
					for (var alert_id in row.alerts) {
						if (active_alerts[alert_id]) { yes_alert = true; break; }
					} // foreach alert
					
					if (yes_alert) alert_times.push( row.date * 1000 );
				} // alerts
				
				last_row = row;
			} // in range
		});
		
		// setup chart series
		var label = this.formatHostname( this.args.hostname );
		var series = [{
			name: label,
			data: self.crushData( graph_rows )
		}];
		
		// setup annotations
		var x_annos = [];
		if (app.getPref('annotations') == '1') {
			alert_times.forEach( function(x) {
				x_annos.push({
					x: x,
					borderColor: '#888',
					yAxisIndex: 0,
					label: {
						show: true,
						text: 'Alert',
						style: {
							color: "#fff",
							background: '#f00'
						}
					}
				});
			});
		} // annotations enabled
		
		// redraw graph series and annos
		var options = this.getGraphConfig(mon_id);
		options.series = series;
		options.annotations = {
			xaxis: x_annos
		};
		graph.updateOptions(options, true, false);
	},
	
	onScrollDebounce: function() {
		// called for redraw, and for scroll (debounced)
		// find all graphs which are dirty AND visible, and update them
		var self = this;
		
		this.div.find('div.graph_container.dirty').each( function() {
			var $this = $(this);
			if (!$this.hasClass('filtered') && $this.visible(true, true)) {
				var mon_id = $this.data('mon');
				Debug.trace('graph', "Rendering graph for scroll event: " + mon_id);
				self.enqueue( self.updateGraph.bind(self, mon_id) );
				$this.removeClass('dirty');
				
				// reset copy icon, just in case
				$this.find('div.graph_button.copy > i').removeClass().addClass('mdi mdi-clipboard-pulse-outline mdi-lg');
			}
		});
	},
	
	onSecond30: function(dargs) {
		// update graphs on the :30s, but only in realtime view
		var args = this.args;
		
		if (this.isRealTime() && (app.getPref('auto_refresh') == '1')) {
			// special case: if we are in an error state, perform a full refresh
			if (!this.graphs) return this.requestData();
			
			var temp_args = copy_object(args);
			temp_args.offset = -1;
			temp_args.length = 1;
			Debug.trace("Requesting graph update on the 30s");
			
			app.api.get( 'app/view/verbose', temp_args, this.receiveUpdate.bind(this), function(err) {
				app.doError( "Server Error: " + err.description );
			} );
		}
	},
	
	onFocus: function() {
		// window received focus, update data
		var args = this.args;
		
		if (this.isRealTime() && (app.getPref('auto_refresh') == '1')) {
			// special case: if we are in an error state, perform a full refresh
			if (!this.graphs) return this.requestData();
			
			Debug.trace("Requesting graph update for focus");
			
			app.api.get( 'app/view/verbose', args, this.receiveUpdate.bind(this), function(err) {
				app.doError( "Server Error: " + err.description );
			} );
		}
	},
	
	receiveUpdate: function(data) {
		// receive update from server
		// data: { code, hostname, rows, metadata }
		var self = this;
		var rows = data.rows;
		var args = this.args;
		
		this.metadata = data.metadata;
		
		if (!rows.length) {
			Debug.trace("No rows found in update, skipping");
			return;
		}
		
		// skip dupes
		var new_rows = [];
		rows.forEach( function(row) {
			if (!find_object(self.rows, { date: row.date })) new_rows.push(row);
		});
		rows = new_rows;
		
		if (!rows.length) {
			Debug.trace("All rows were dupes in update, skipping");
			return;
		}
		
		// data comes in as totals (may be more than one sample per timestamp), so pre-average everything
		rows.forEach( function(row) {
			for (var key in row.totals) {
				row.totals[key] /= row.count || 1;
			}
			self.rows.push( row );
		});
		
		// sort just in case
		this.rows = this.rows.sort( function(a, b) {
			return (a.date - b.date);
		});
		
		// discard old if beyond length
		while (this.rows.length > args.length) this.rows.shift();
		
		// we need to apply range minimum and maximum again, because time moves forward
		this.calcDataRange();
		
		// update and render data range display in control strip
		this.updateDataRangeDisplay();
		
		// trigger visible graph redraw (also happens on debounced scroll)
		this.div.find('div.graph_container').addClass('dirty');
		this.onScrollDebounce();
		this.updateInfo();
	},
	
	createPie: function(pie) {
		// create pie (donut) chart with apex
		// pie: { id, title, subtitle, value, max }
		var $cont = this.div.find('#' + pie.id);
		var $elem = $cont.find('div.server_pie_graph');
		var $overlay = $cont.find('div.server_pie_overlay');
		
		$overlay.html(
			'<div class="pie_overlay_title">' + pie.title + '</div>' + 
			'<div class="pie_overlay_subtitle">' + pie.subtitle + '</div>'
		);
		$overlay.attr('title', pie.tooltip || '');
		
		if (pie.value > pie.max) pie.value = pie.max;
		else if (pie.value < 0) pie.value = 0;
		
		var series = [ pie.value, pie.max - pie.value ];
		var amount = pie.value / pie.max;
		
		var color = '';
		if (amount >= 0.75) color = 'rgba(255, 0, 0, 0.75)';
		else if (amount >= 0.5) color = 'rgba(224, 224, 0, 0.85)';
		else color = '#080';
		var colors = [ color, 'rgba(128, 128, 128, 0.2)' ];
		
		var options = {
			chart: {
				type: 'donut',
				width: 180,
				height: 180,
				animations: {
					enabled: false
				}
			},
			dataLabels: {
				enabled: false
			},
			series: series,
			colors: colors,
			plotOptions: {
				pie: {
					// customScale: 1.4,
					offsetY: 33,
					size: 84,
					donut: {
						size: '55%',
						background: 'transparent',
						labels: {
							show: false
						}
					},
					expandOnClick: false
				}
			},
			stroke: {
				show: false
			},
			legend: {
				show: false
			},
			tooltip: {
				enabled: false
			}
		}; // options
		
		var chart = new ApexCharts( $elem.get(0), options );
		chart.render();
		return chart;
	},
	
	updatePie: function(chart, pie) {
		// update donut value
		// pie: { id, subtitle, value, max }
		var $cont = this.div.find('#' + pie.id);
		var $overlay = $cont.find('div.server_pie_overlay');
		
		$overlay.find('.pie_overlay_subtitle').html( pie.subtitle );
		$overlay.attr('title', pie.tooltip || '');
		
		if (pie.value > pie.max) pie.value = pie.max;
		else if (pie.value < 0) pie.value = 0;
		
		var series = [ pie.value, pie.max - pie.value ];
		var amount = pie.value / pie.max;
		
		var color = '';
		if (amount >= 0.75) color = 'rgba(255, 0, 0, 0.75)';
		else if (amount >= 0.5) color = 'rgba(224, 224, 0, 0.85)';
		else color = '#080';
		var colors = [ color, 'rgba(128, 128, 128, 0.2)' ];
		
		var options = {
			series: series,
			colors: colors
		};
		
		chart.updateOptions( options, true, false );
	},
	
	updateInfo: function() {
		// update server alerts and info
		var self = this;
		var args = this.args;
		var metadata = this.metadata;
		
		// gather alerts in realtime mode
		var all_alerts = [];
		if (metadata.alerts) {
			for (var alert_id in metadata.alerts) {
				all_alerts.push( 
					merge_objects( metadata.alerts[alert_id], { 
						id: alert_id, 
						hostname: args.hostname 
					} )
				);
			} // foreach alert
		} // has alerts
		
		if (all_alerts.length && this.isRealTime()) {
			// build alert table
			var html = '';
			html += '<legend style="color:red">Current Alerts</legend>';
			html += '<table class="fieldset_table" width="100%">';
			html += '<tr>';
				html += '<th>Alert</th>';
				html += '<th>Hostname</th>';
				html += '<th>Detail</th>';
				html += '<th>Trigger</th>';
				html += '<th>Date/Time</th>';
				html += '<th>Actions</th>';
			html += '</tr>';
			
			all_alerts.forEach( function(alert) {
				var alert_def = find_object( config.alerts, { id: alert.id } ) || { 
					id: alert.id,
					title: '(' + alert.id + ')',
					expression: 'n/a'
				};
				html += '<tr>';
				html += '<td><b>' + self.getNiceAlert(alert_def, true) + '</b></td>';
				html += '<td>' + self.getNiceHostname(alert.hostname, false) + '</td>';
				html += '<td>' + alert.message + '</td>';
				html += '<td style="font-family:monospace">' + alert_def.expression + '</pre></td>';
				html += '<td>' + get_nice_date_time( alert.date ) + '</td>';
				
				var snap_id = alert.hostname + '/' + Math.floor( alert.date / 60 );
				html += '<td><a href="#Snapshot?id=' + snap_id + '">View&nbsp;Snapshot</a></td>';
				html += '</tr>';
			});
			
			html += '</table>';
			this.div.find('#fs_server_alerts').empty().html(html).show();
		}
		else {
			// no alerts, hide entire fieldset
			this.div.find('#fs_server_alerts').empty().hide();
		}
		
		// any filter at all hides info fieldset
		if (app.monitorFilter) {
			if (this.cpu_graph) {
				this.cpu_graph.destroy();
				delete this.cpu_graph;
			}
			if (this.mem_graph) {
				this.mem_graph.destroy();
				delete this.mem_graph;
			}
			if (this.disk_graph) {
				this.disk_graph.destroy();
				delete this.disk_graph;
			}
			this.div.find('#fs_server_info').empty().hide();
			this.div.find('#fs_server_cpus').empty().hide();
			return;
		}
		
		var cpu_tooltip = '';
		var mem_tooltip = '';
		var disk_tooltip = '';
		
		if (metadata.data.load) {
			var nice_load = metadata.data.load.map( function(num) { return short_float_str(num); } ).join(', ');
			cpu_tooltip = "Load Averages: " + nice_load;
		}
		if (metadata.data.memory) {
			var mem = metadata.data.memory;
			mem_tooltip = get_text_from_bytes(mem.used) + " of " + get_text_from_bytes(mem.total) + " in use, " + get_text_from_bytes(mem.available) + " available (" + get_text_from_bytes(mem.free) + " free)";
		}
		if (metadata.data.mounts && metadata.data.mounts.root) {
			var root_mount = metadata.data.mounts.root;
			var avail_bytes = Math.max(0, root_mount.size - root_mount.used);
			disk_tooltip = get_text_from_bytes(root_mount.used) + " of " + get_text_from_bytes(root_mount.size) + " in use, " + get_text_from_bytes(avail_bytes) + " available";
		}
		
		// server info table: fs_server_info
		if (this.cpu_graph) {
			// update existing graphs, do not redraw
			this.updatePie( this.cpu_graph, {
				id: 'd_server_pie_cpu',
				subtitle: short_float_str(metadata.data.load ? metadata.data.load[0] : 0),
				value: metadata.data.load ? metadata.data.load[0] : 0,
				max: metadata.data.cpu ? metadata.data.cpu.cores : 0,
				tooltip: cpu_tooltip
			});
			
			this.updatePie( this.mem_graph, {
				id: 'd_server_pie_mem',
				subtitle: get_text_from_bytes(metadata.data.memory.used || 0),
				value: metadata.data.memory.used || 0,
				max: metadata.data.memory.total || 0,
				tooltip: mem_tooltip
			});
			
			this.updatePie( this.disk_graph, {
				id: 'd_server_pie_disk',
				subtitle: pct( metadata.data.mounts.root.use, 100, false ),
				value: metadata.data.mounts.root.use || 0,
				max: 100,
				tooltip: disk_tooltip
			});
			
			// uptime may change
			this.div.find('#d_server_uptime').html( get_text_from_seconds(metadata.data.uptime_sec || 0, false, true) );
		}
		else if (this.isRealTime()) {
			// build content
			var html = '';
			html += '<legend>Current Server Info</legend>';
			
			// flex (god help me)
			html += '<div style="display:flex; justify-content:space-between; margin:5px 10px 0px 10px;">';
			
			// column 1 (info)
			html += '<div class="server_info_column">';
				html += '<div class="info_label">Hostname</div>';
				html += '<div class="info_value">' + args.hostname + '</div>';
				
				html += '<div class="info_label">IP Address</div>';
				html += '<div class="info_value">' + (metadata.ip || 'n/a') + '</div>';
				
				var group_def = find_object( config.groups, { id: metadata.group } ) || { 
					id: metadata.group,
					title: '(' + metadata.group + ')'
				};
				
				var query = { group: metadata.group };
				if (this.args && this.args.sys) query.sys = this.args.sys;
				if (this.args && this.args.date) query.date = this.args.date;
				if (this.args && ('offset' in this.args)) query.offset = this.args.offset;
				if (this.args && this.args.length) query.length = this.args.length;
				
				// this.formatHostname(args.hostname)
				// metadata.ip
				
				html += '<div class="info_label">Group Membership</div>';
				// html += '<div class="info_value">' + this.getNiceGroup(group_def, '#Group' + compose_query_string(query)) + '</div>';
				html += '<div class="info_value">' + this.getNiceGroup(group_def, false) + '</div>';
				
				var nice_cores = 'n/a';
				if (metadata.data.cpu && metadata.data.cpu.cores) {
					if (metadata.data.cpu.physicalCores && (metadata.data.cpu.physicalCores != metadata.data.cpu.cores)) {
						nice_cores = metadata.data.cpu.physicalCores + " physical, " + 
							metadata.data.cpu.cores + " virtual";
					}
					else {
						nice_cores = metadata.data.cpu.cores;
					}
				}
				html += '<div class="info_label">CPU Cores</div>';
				html += '<div class="info_value">' + nice_cores + '</div>';
				
				html += '<div class="info_label">Total RAM</div>';
				html += '<div class="info_value">' + get_text_from_bytes(metadata.data.memory.total || 0) + '</div>';
			html += '</div>';
			
			// column 1B (info cont)
			html += '<div class="server_info_column">';
				var nice_cpu_model = 'n/a';
				if (metadata.data.cpu && metadata.data.cpu.manufacturer) {
					nice_cpu_model = metadata.data.cpu.manufacturer;
					if (metadata.data.cpu.brand) nice_cpu_model += ' ' + metadata.data.cpu.brand;
				}
				html += '<div class="info_label">CPU Type</div>';
				html += '<div class="info_value">' + nice_cpu_model + '</div>';
				
				var clock_ghz = metadata.data.cpu ? metadata.data.cpu.speed : 0;
				var nice_clock_speed = '' + clock_ghz + ' GHz';
				if (clock_ghz < 1.0) {
					nice_clock_speed = Math.floor(clock_ghz * 1000) + ' MHz';
				}
				html += '<div class="info_label">CPU Clock</div>';
				html += '<div class="info_value">' + nice_clock_speed + '</div>';
				
				var nice_os = 'n/a';
				if (metadata.data.os.distro) {
					nice_os = metadata.data.os.distro + ' ' + metadata.data.os.release; //  + ' (' + metadata.data.os.arch + ')';
				}
				html += '<div class="info_label">Operating System</div>';
				html += '<div class="info_value">' + nice_os + '</div>';
				
				var nice_kernel = 'n/a';
				var extra_server_info = config.extra_server_info;
				if (extra_server_info.source) {
					nice_kernel = substitute(extra_server_info.source, metadata.data, false);
				}
				html += '<div class="info_label">' + extra_server_info.title + '</div>';
				html += '<div class="info_value">' + nice_kernel + '</div>';
				
				html += '<div class="info_label">Uptime</div>';
				html += '<div id="d_server_uptime" class="info_value" style="margin-bottom:0;">' + get_text_from_seconds(metadata.data.uptime_sec || 0, false, true) + '</div>';
			html += '</div>';
			
			// column 2 (cpu graph)
			html += '<div class="server_info_column">';
				html += '<div id="d_server_pie_cpu" class="server_pie_container"><div class="server_pie_graph"></div><div class="server_pie_overlay"></div></div>';
			html += '</div>';
			
			// column 3 (mem graph)
			html += '<div class="server_info_column">';
				html += '<div id="d_server_pie_mem" class="server_pie_container"><div class="server_pie_graph"></div><div class="server_pie_overlay"></div></div>';
			html += '</div>';
			
			// column 4 (disk graph)
			html += '<div class="server_info_column">';
				html += '<div id="d_server_pie_disk" class="server_pie_container"><div class="server_pie_graph"></div><div class="server_pie_overlay"></div></div>';
			html += '</div>';
			
			// html += '<div class="clear"></div>';
			html += '</div>';
			this.div.find('#fs_server_info').empty().html(html).show();
			
			// create pie graphs
			this.cpu_graph = this.createPie({
				id: 'd_server_pie_cpu',
				title: 'Load',
				subtitle: short_float_str(metadata.data.load ? metadata.data.load[0] : 0),
				value: metadata.data.load ? metadata.data.load[0] : 0,
				max: metadata.data.cpu ? metadata.data.cpu.cores : 0,
				tooltip: cpu_tooltip
			});
			
			this.mem_graph = this.createPie({
				id: 'd_server_pie_mem',
				title: 'Mem',
				subtitle: get_text_from_bytes(metadata.data.memory.used || 0),
				value: metadata.data.memory.used || 0,
				max: metadata.data.memory.total || 0,
				tooltip: mem_tooltip
			});
			
			this.disk_graph = this.createPie({
				id: 'd_server_pie_disk',
				title: 'Disk',
				subtitle: pct( metadata.data.mounts.root.use, 100, false ),
				value: metadata.data.mounts.root.use || 0,
				max: 100,
				tooltip: disk_tooltip
			});
		}
		else {
			// not real-time, hide entire fieldset
			this.div.find('#fs_server_info').empty().hide();
		}
		
		// cpu details
		if (this.isRealTime() && metadata.data.cpu.cpus && num_keys(metadata.data.cpu.cpus)) {
			this.div.find('#fs_server_cpus').html( 
				this.getCPUTableHTML( metadata.data.cpu.cpus ) 
			).show();
		}
		else {
			// not real-time or no cpu details, hide entire fieldset
			this.div.find('#fs_server_cpus').empty().hide();
		}
	},
	
	applyMonitorFilter: function(initial) {
		// hide/show graphs based on current filter text
		if (!this.monitors || !this.monitors.length) return;
		var self = this;
		var filterMatch = new RegExp( escape_regexp(app.monitorFilter || '') || '.+', "i" );
		var changes = 0;
		var num_filtered = 0;
		
		this.monitors.forEach( function(mon_def, idx) {
			var visible = !!(mon_def.title.match(filterMatch) || mon_def.id.match(filterMatch));
			var $cont = self.div.find('#d_graph_server_' + mon_def.id);
			
			if (visible && $cont.hasClass('filtered')) {
				$cont.removeClass('filtered').addClass('dirty');
				changes++;
			}
			else if (!visible && !$cont.hasClass('filtered')) {
				$cont.addClass('filtered');
				changes++;
			}
			if (!visible) num_filtered++;
		});
		
		if (changes && !initial) {
			this.onScrollDebounce();
		}
		if (!initial) {
			this.updateInfo();
		}
		if (num_filtered == this.monitors.length) {
			this.div.find('#fs_all_filtered').show();
		}
		else {
			this.div.find('#fs_all_filtered').hide();
		}
	},
	
	editServerWatch: function() {
		// open server watch dialog
		var self = this;
		var args = this.args;
		var html = '';
		var watch_sel = 0;
		var state = config.state;
		
		var watch_items = [
			[0, "(Disable Watch)"],
			app.getTimeMenuItem( 60 ),
			app.getTimeMenuItem( 60 * 5 ),
			app.getTimeMenuItem( 60 * 10 ),
			app.getTimeMenuItem( 60 * 15 ),
			app.getTimeMenuItem( 60 * 30 ),
			app.getTimeMenuItem( 60 * 45 ),
			app.getTimeMenuItem( 3600 ),
			app.getTimeMenuItem( 3600 * 2 ),
			app.getTimeMenuItem( 3600 * 3 ),
			app.getTimeMenuItem( 3600 * 6 ),
			app.getTimeMenuItem( 3600 * 12 ),
			app.getTimeMenuItem( 86400 ),
			app.getTimeMenuItem( 86400 * 2 ),
			app.getTimeMenuItem( 86400 * 3 ),
			app.getTimeMenuItem( 86400 * 7 ),
			app.getTimeMenuItem( 86400 * 15 ),
			app.getTimeMenuItem( 86400 * 30 )
		];
		
		if (state.watches && state.watches[args.hostname] && (state.watches[args.hostname] > time_now())) {
			// watch is currently enabled
			html += '<div style="font-size:12px; margin-bottom:20px;">A watch is currently <b>enabled</b> on this server, and will be until <b>' + get_nice_date_time(state.watches[args.hostname], false, false) + '</b> (approximately ' + get_text_from_seconds(state.watches[args.hostname] - time_now(), false, true) + ' from now).  Use the menu below to reset the watch, or disable it entirely.</div>';
			watch_sel = 0;
		}
		else {
			// watch is disabled
			html += '<div style="font-size:12px; margin-bottom:20px;">This server is not currently being watched.  Use the menu below to optionally set a watch timer, which will generate snapshots every minute until the timer expires.</div>';
			watch_sel = 3600;
		}
		
		html += '<center><table>' + 
			// get_form_table_spacer() + 
			get_form_table_row('Watch For:', '<select id="fe_watch_time">' + render_menu_options(watch_items, watch_sel) + '</select>') + 
			get_form_table_caption("Select the duration for the server watch.") + 
		'</table></center>';
		
		app.confirm( '<i class="mdi mdi-eye">&nbsp;</i>Watch Server', html, "Set Watch", function(result) {
			app.clearError();
			
			if (result) {
				var watch_time = parseInt( $('#fe_watch_time').val() );
				var watch_date = time_now() + watch_time;
				Dialog.hide();
				
				app.api.post( 'app/watch', { hostnames: [args.hostname], date: watch_date }, function(resp) {
					// update local state and show message
					if (!state.watches) state.watches = {};
					
					if (watch_time) {
						app.showMessage('success', "Server will be watched for " + get_text_from_seconds(watch_time, false, true) + ".");
						state.watches[ args.hostname ] = watch_date;
					}
					else {
						app.showMessage('success', "Server watch has been disabled.");
						delete state.watches[ args.hostname ];
					}
					
				} ); // api.post
			} // user clicked set
		} ); // app.confirm
	},
	
	takeSnapshot: function() {
		// take a snapshot (i.e. 1 minute watch)
		var args = this.args;
		var state = config.state;
		var watch_time = 60;
		var watch_date = time_now() + watch_time;
		
		app.api.post( 'app/watch', { hostnames: [args.hostname], date: watch_date }, function(resp) {
			// update local state and show message
			if (!state.watches) state.watches = {};
			app.showMessage('success', 'Your snapshot will be taken within a minute, and appear on the <a href="#Snapshot">Snapshots</a> tab.');
			state.watches[ args.hostname ] = watch_date;
		} ); // api.post
	},
	
	onThemeChange: function(theme) {
		// user has changed theme, update graphs
		if (this.graphs) {
			this.div.find('div.graph_container').addClass('dirty');
			this.onScrollDebounce();
		}
	},
	
	onDeactivate: function() {
		// called when page is deactivated
		if (this.graphs) {
			for (var key in this.graphs) {
				this.graphs[key].destroy();
			}
		}
		if (this.cpu_graph) {
			this.cpu_graph.destroy();
			delete this.cpu_graph;
		}
		if (this.mem_graph) {
			this.mem_graph.destroy();
			delete this.mem_graph;
		}
		if (this.disk_graph) {
			this.disk_graph.destroy();
			delete this.disk_graph;
		}
		
		this.queue = [];
		if (this.queueTimer) clearTimeout( this.queueTimer );
		this.graphs = null;
		this.div.html( '' );
		return true;
	}
	
} );

Class.subclass( Page.Base, "Page.Snapshot", {	
	
	default_sub: 'list',
	
	onInit: function() {
		// called once at page load
		var html = '';
		this.div.html( html );
	},
	
	onActivate: function(args) {
		// page activation
		if (!this.requireLogin(args)) return true;
		
		if (!args) args = {};
		if (args.id) args.sub = 'snapshot';
		if (!args.sub) args.sub = this.default_sub;
		this.args = args;
		
		app.showTabBar(true);
		this.showControls(false);
		
		this.div.addClass('loading');
		this['gosub_'+args.sub](args);
		
		return true;
	},
	
	gosub_list: function(args) {
		// show snapshot list
		app.setWindowTitle( "Snapshot List" );
		
		if (!args.offset) args.offset = 0;
		if (!args.limit) args.limit = 25;
		app.api.post( 'app/get_snapshots', copy_object(args), this.receive_snapshots.bind(this) );
	},
	
	receive_snapshots: function(resp) {
		// receive page of snapshots from server, render it
		var self = this;
		var html = '';
		this.div.removeClass('loading');
		
		this.snapshots = [];
		if (resp.rows) this.snapshots = resp.rows;
		
		var cols = ['Hostname', 'Date/Time', 'Source', 'Alerts', 'Actions'];
		
		html += '<div style="padding:20px 20px 30px 20px">';
		
		html += '<div class="subtitle">';
			html += 'Server Snapshot List';
			// html += '<div class="clear"></div>';
		html += '</div>';
		
		if (resp.rows && resp.rows.length) {
			html += this.getPaginatedTable( resp, cols, 'snapshot', function(item, idx) {
				// { date, hostname, source, alerts, time_code }
				var color = '';
				var snap_id = item.hostname + '/' + item.time_code;
				var snap_url = '#Snapshot?id=' + snap_id;
				var actions = [ '<a href="' + snap_url + '">View Snapshot</a>' ];
				var nice_source = '';
				var nice_alerts = '(None)';
				
				switch (item.source) {
					case 'alert': nice_source = '<i class="mdi mdi-bell">&nbsp;</i>Alert System'; break;
					case 'watch': nice_source = '<i class="mdi mdi-eye">&nbsp;</i>Server Watch'; break;
				}
				
				if (item.alerts && num_keys(item.alerts)) {
					nice_alerts = hash_keys_to_array(item.alerts).sort().map( function(alert_id) {
						var alert_def = find_object( config.alerts, { id: alert_id } ) || { 
							id: alert.id,
							title: '(' + alert.id + ')',
							expression: 'n/a'
						};
						return '<i class="mdi mdi-bell">&nbsp;</i>' + alert_def.title;
					}).join(', ');
				}
				
				var tds = [
					'<b>' + self.getNiceHostname( item.hostname, snap_url ) + '</b>',
					'<div style="white-space:nowrap;">' + get_nice_date_time( item.date || 0, false, false ) + '</div>',
					'<div class="td_big" style="white-space:nowrap; font-size:12px; font-weight:normal;">' +  nice_source + '</div>',
					// nice_source,
					nice_alerts,
					'<div style="white-space:nowrap;">' + actions.join(' | ') + '</div>'
				];
				if (color) tds.className = color;
				
				return tds;
			} );
		}
		else {
			html += '<fieldset class="inline_error">';
			html += '<div class="inline_error_title">No Snapshots Found</div>';
			html += '<div class="inline_error_msg">Snapshots are automatically created when an alert is triggered.<br/>You can also request snapshots on any server by starting a <i class="mdi mdi-eye">&nbsp;</i>Watch.</div>';
			html += '</fieldset>';
		}
		
		html += '</div>'; // padding
		
		this.div.html( html );
	},
	
	getNiceHostname: function(hostname, link, width) {
		// get formatted hostname with icon, plus custom link
		if (!width) width = 500;
		if (!hostname) return '(None)';
		
		var html = '<div class="ellip" style="max-width:' + width + 'px;">';
		var icon = '<i class="mdi mdi-desktop-tower">&nbsp;</i>';
		if (link) {
			html += '<a href="' + link + '" style="text-decoration:none">';
			html += icon + '<span style="text-decoration:underline">' + this.formatHostname(hostname) + '</span></a>';
		}
		else {
			html += icon + this.formatHostname(hostname);
		}
		html += '</div>';
		
		return html;
	},
	
	gosub_snapshot: function(args) {
		// show specific snapshot
		var self = this;
		var args = this.args;
		
		app.setWindowTitle( "View Snapshot" );
		
		app.api.get( 'app/get_snapshot', args, this.receiveSnapshot.bind(this), function(err) {
			self.doInlineError( "Server Error", err.description );
		} );
	},
	
	jumpToHistorical: function() {
		// jump to historical view for snapshot date and hostname
		var hostname = this.metadata.hostname;
		var date = this.metadata.date;
		var dargs = get_date_args( date );
		Nav.go( '#Server?hostname=' + hostname + '&date=' + dargs.yyyy_mm_dd + '/' + dargs.hh );
	},
	
	receiveSnapshot: function(resp) {
		// render snapshot data
		var self = this;
		var args = this.args;
		this.div.removeClass('loading');
		this.metadata = resp.metadata;
		var metadata = resp.metadata;
		var snapshot = metadata.snapshot;
		var html = '';
		
		this.group = app.findGroupFromHostData( metadata );
		if (!this.group) {
			this.group = { id: "(unknown)", title: "(Unknown)" };
			// return this.doInlineError("No matching group found for server: " + this.args.hostname);
		}
		
		html += '<div class="subtitle" style="margin-top:10px; margin-bottom:15px;">';
			html += '<i class="mdi mdi-history">&nbsp;</i>Server Snapshot: ' + app.formatHostname(metadata.hostname) + " &mdash; " + get_nice_date_time( metadata.date );
			html += '<div class="subtitle_widget"><span class="link" onMouseUp="$P().jumpToHistorical()"><i class="mdi mdi-chart-line mdi-lg">&nbsp;</i><b>View Historical Graphs...</b></span></div>';
			html += '<div class="clear"></div>';
		html += '</div>';
		
		// gather alerts from snapshot
		var all_alerts = [];
		if (metadata.alerts) {
			for (var alert_id in metadata.alerts) {
				all_alerts.push( 
					merge_objects( metadata.alerts[alert_id], { 
						id: alert_id, 
						hostname: metadata.hostname 
					} )
				);
			} // foreach alert
		} // has alerts
		
		if (all_alerts.length) {
			// build alert table
			html += '<fieldset style="margin-top:10px">';
			html += '<legend>Alerts</legend>';
			html += '<table class="fieldset_table" width="100%">';
			html += '<tr>';
				html += '<th>Alert</th>';
				html += '<th>Hostname</th>';
				html += '<th>Detail</th>';
				html += '<th>Trigger</th>';
				html += '<th>Date/Time</th>';
			html += '</tr>';
			
			all_alerts.forEach( function(alert) {
				var alert_def = find_object( config.alerts, { id: alert.id } ) || { 
					id: alert.id,
					title: '(' + alert.id + ')',
					expression: 'n/a'
				};
				html += '<tr>';
				html += '<td><b>' + self.getNiceAlert(alert_def, true) + '</b></td>';
				html += '<td>' + self.getNiceHostname(alert.hostname, false) + '</td>';
				html += '<td>' + alert.message + '</td>';
				html += '<td style="font-family:monospace">' + alert_def.expression + '</pre></td>';
				html += '<td>' + get_nice_date_time( alert.date ) + '</td>';
				html += '</tr>';
			});
			
			html += '</table>';
			html += '</fieldset>';
		}
		
		html += '<fieldset style="margin-top:10px;">';
		html += '<legend>Server Info</legend>';
		
		// flex (god help me)
		html += '<div style="display:flex; justify-content:space-between; margin:5px 10px 0px 10px;">';
		
		// column 1
		html += '<div class="snap_info_column">';
			html += '<div class="info_label">Snapshot Date/Time</div>';
			html += '<div class="info_value">' + get_nice_date_time( metadata.date ) + '</div>';
			
			html += '<div class="info_label">Hostname</div>';
			html += '<div class="info_value">' + metadata.hostname + '</div>';
			
			html += '<div class="info_label">IP Address</div>';
			html += '<div class="info_value">' + (metadata.ip || 'n/a') + '</div>';
			
			html += '<div class="info_label">Group Membership</div>';
			html += '<div class="info_value">' + this.getNiceGroup(this.group, false) + '</div>';
		html += '</div>';
		
		// column 2
		html += '<div class="snap_info_column">';
			var nice_cpu_model = 'n/a';
			if (metadata.data.cpu && metadata.data.cpu.manufacturer) {
				nice_cpu_model = metadata.data.cpu.manufacturer;
				if (metadata.data.cpu.brand) nice_cpu_model += ' ' + metadata.data.cpu.brand;
			}
			html += '<div class="info_label">CPU Type</div>';
			html += '<div class="info_value">' + nice_cpu_model + '</div>';
			
			var clock_ghz = metadata.data.cpu ? metadata.data.cpu.speed : 0;
			var nice_clock_speed = '' + clock_ghz + ' GHz';
			if (clock_ghz < 1.0) {
				nice_clock_speed = Math.floor(clock_ghz * 1000) + ' MHz';
			}
			html += '<div class="info_label">CPU Clock</div>';
			html += '<div class="info_value">' + nice_clock_speed + '</div>';
			
			var nice_cores = 'n/a';
			if (metadata.data.cpu && metadata.data.cpu.cores) {
				if (metadata.data.cpu.physicalCores && (metadata.data.cpu.physicalCores != metadata.data.cpu.cores)) {
					nice_cores = metadata.data.cpu.physicalCores + " physical, " + 
						metadata.data.cpu.cores + " virtual";
				}
				else {
					nice_cores = metadata.data.cpu.cores;
				}
			}
			html += '<div class="info_label">CPU Cores</div>';
			html += '<div class="info_value">' + nice_cores + '</div>';
			
			var nice_load = metadata.data.load.map( function(num) { return short_float_str(num); } ).join(', ');
			html += '<div class="info_label">CPU Load Averages</div>';
			html += '<div class="info_value">' + nice_load + '</div>';
		html += '</div>';
		
		// column 3
		html += '<div class="snap_info_column">';
			html += '<div class="info_label">Total RAM</div>';
			html += '<div class="info_value">' + get_text_from_bytes(metadata.data.memory.total || 0) + '</div>';
			
			html += '<div class="info_label">Memory in Use</div>';
			html += '<div class="info_value">' + get_text_from_bytes(metadata.data.memory.used || 0) + '</div>';
			
			html += '<div class="info_label">Memory Available</div>';
			html += '<div class="info_value">' + get_text_from_bytes(metadata.data.memory.available || 0) + '</div>';
			
			html += '<div class="info_label">Memory Free</div>';
			html += '<div class="info_value">' + get_text_from_bytes(metadata.data.memory.free || 0) + '</div>';
		html += '</div>';
		
		// column 4
		html += '<div class="snap_info_column">';
			var socket_states = metadata.data.stats.network.states || {};
			html += '<div class="info_label">Socket Listeners</div>';
			html += '<div class="info_value">' + commify( socket_states.listen || 0 ) + '</div>';
			
			html += '<div class="info_label">Open Connections</div>';
			html += '<div class="info_value">' + commify( socket_states.established || 0 ) + '</div>';
			
			var num_closed = 0;
			if (socket_states.close_wait) num_closed += socket_states.close_wait;
			if (socket_states.closed) num_closed += socket_states.closed;
			html += '<div class="info_label">Closed Connections</div>';
			html += '<div class="info_value">' + commify( num_closed ) + '</div>';
			
			html += '<div class="info_label">Total Processes</div>';
			html += '<div class="info_value">' + commify( metadata.data.processes.all || 0 ) + '</div>';
		html += '</div>';
		
		// column 5
		html += '<div class="snap_info_column">';
			var nice_disk = 'n/a';
			var root_mount = metadata.data.mounts.root;
			if (root_mount) {
				nice_disk = get_text_from_bytes(root_mount.used) + " of " + get_text_from_bytes(root_mount.size) + " (" + root_mount.use + "%)";
			}
			html += '<div class="info_label">Disk Usage (Root)</div>';
			html += '<div class="info_value">' + nice_disk + '</div>';
			
			var nice_os = 'n/a';
			if (metadata.data.os.distro) {
				nice_os = metadata.data.os.distro + ' ' + metadata.data.os.release; //  + ' (' + metadata.data.os.arch + ')';
			}
			html += '<div class="info_label">Operating System</div>';
			html += '<div class="info_value">' + nice_os + '</div>';
			
			var nice_kernel = 'n/a';
			var extra_server_info = config.extra_server_info;
			if (extra_server_info.source) {
				nice_kernel = substitute(extra_server_info.source, metadata.data, false);
			}
			html += '<div class="info_label">' + extra_server_info.title + '</div>';
			html += '<div class="info_value">' + nice_kernel + '</div>';
			
			html += '<div class="info_label">Server Uptime</div>';
			html += '<div id="d_server_uptime" class="info_value" style="margin-bottom:0;">' + get_text_from_seconds(metadata.data.uptime_sec || 0, false, true) + '</div>';
		html += '</div>';
		
		html += '</div>'; // flex
		html += '</fieldset>';
		
		// CPU Details
		if (metadata.data.cpu && metadata.data.cpu.cpus) {
			html += '<fieldset style="margin-top:10px;">';
			html += this.getCPUTableHTML( metadata.data.cpu.cpus );
			html += '</fieldset>';
		}
		
		// Processes
		snapshot.processes.list.forEach( function(item) {
			var epoch = ((new Date( item.started.replace(/\-/g, '/') )).getTime() || 0) / 1000;
			item.age = epoch ? Math.max(0, metadata.date - epoch) : 0;
		});
		
		var proc_opts = {
			id: 't_snap_procs',
			item_name: 'process',
			sort_by: 'pcpu',
			sort_dir: -1,
			filter: '',
			column_ids: ['pid', 'parentPid', 'user', 'pcpu', 'mem_rss', 'age', 'command'],
			column_labels: ["PID", "Parent", "User", "CPU", "Memory", "Age", "Command"]
		};
		html += '<fieldset style="margin-top:10px;">';
		html += '<legend>All Processes</legend>';
		html += '<div class="inline_table_scrollarea">';
		html += this.getSortableTable( snapshot.processes.list, proc_opts, function(item) {
			return [
				item.pid,
				item.parentPid,
				item.user,
				short_float(item.pcpu) + '%',
				'<div style="white-space:nowrap;">' + get_text_from_bytes( (item.mem_rss || 0) * 1024 ) + '</div>',
				'<div style="white-space:nowrap;">' + get_text_from_seconds( item.age || 0, false, true ) + '</div>',
				'<span style="font-family:monospace; white-space:normal; word-break:break-word;">' + item.command + '</span>'
			];
		});
		html += '</div>';
		html += '</fieldset>';
		
		// Connections
		snapshot.network.connections.forEach( function(item) {
			item.localport = parseInt( item.localport ) || 0;
			item.peerport = parseInt( item.peerport ) || 0;
		});
		var conn_opts = {
			id: 't_snap_conns',
			item_name: 'connection',
			sort_by: 'peeraddress',
			sort_dir: 1,
			filter: 'established',
			column_ids: ['protocol', 'localaddress', 'localport', 'peeraddress', 'peerport', 'state'],
			column_labels: ["Protocol", "Local Address", "Local Port", "Peer Address", "Peer Port", "State"]
		};
		html += '<fieldset style="margin-top:10px;">';
		html += '<legend>Network Connections</legend>';
		html += '<div class="inline_table_scrollarea">';
		html += this.getSortableTable( snapshot.network.connections, conn_opts, function(item) {
			return [
				item.protocol.toUpperCase(),
				item.localaddress,
				item.localport,
				item.peeraddress,
				item.peerport,
				item.state
			];
		});
		html += '</div>';
		html += '</fieldset>';
		
		// Open Files
		if (snapshot.files && snapshot.files.list && snapshot.files.list.length) {
			var files_opts = {
				id: 't_snap_files',
				item_name: 'file',
				sort_by: 'pid',
				sort_dir: 1,
				filter: '',
				column_ids: ['pid', 'type', 'desc', 'path'],
				column_labels: ["PID", "Type", "Description", "Path/Info"]
			};
			html += '<fieldset style="margin-top:10px;">';
			html += '<legend>Open Files</legend>';
			html += '<div class="inline_table_scrollarea">';
			html += this.getSortableTable( snapshot.files.list, files_opts, function(item) {
				return [
					item.pid,
					item.type,
					item.desc,
					'<span style="font-family:monospace; white-space:normal; word-break:break-word;">' + item.path + '</span>'
				];
			});
			html += '</div>';
			html += '</fieldset>';
		}
		
		// Filesystems
		var mounts = [];
		for (var key in metadata.data.mounts) {
			var mount = metadata.data.mounts[key];
			mount.avail = Math.max(0, mount.size - mount.used);
			mounts.push( mount );
		}
		var fs_opts = {
			id: 't_snap_fs',
			item_name: 'mount',
			sort_by: 'mount',
			sort_dir: 1,
			filter: '',
			column_ids: ['mount', 'type', 'fs', 'size', 'used', 'avail', 'use'],
			column_labels: ["Mount Point", "Type", "Device", "Total Size", "Used", "Available", "Use %"]
		};
		html += '<fieldset style="margin-top:10px;">';
		html += '<legend>Filesystems</legend>';
		html += '<div class="inline_table_scrollarea">';
		html += this.getSortableTable( mounts, fs_opts, function(item) {
			return [
				'<span style="font-family:monospace">' + item.mount + '</span>',
				item.type,
				item.fs,
				get_text_from_bytes( item.size ),
				get_text_from_bytes( item.used ),
				get_text_from_bytes( item.avail ),
				self.getPercentBarHTML( item.use / 100, 200 )
			];
		});
		html += '</div>';
		html += '</fieldset>';
		
		this.div.html( html );
	},
	
	getSortedTableRows: function(id) {
		// get sorted (and filtered!) table rows
		var opts = this.tables[id];
		var filter_re = new RegExp( escape_regexp(opts.filter) || '.*', 'i' );
		var sort_by = opts.sort_by;
		var sort_dir = opts.sort_dir;
		var sort_type = 'number';
		if (opts.rows.length && (typeof(opts.rows[0][sort_by]) == 'string')) sort_type = 'string';
		
		// apply filter
		var rows = opts.rows.filter( function(row) {
			var blob = hash_values_to_array(row).join(' ');
			return !!blob.match( filter_re );
		} );
		
		// apply custom sort
		rows.sort( function(a, b) {
			if (sort_type == 'number') {
				return( (a[sort_by] - b[sort_by]) * sort_dir );
			}
			else {
				return( a[sort_by].toString().localeCompare(b[sort_by]) * sort_dir );
			}
		});
		
		return rows;
	},
	
	applyTableFilter: function(elem) {
		// key typed in table filter box, redraw
		var id = $(elem).data('id');
		var opts = this.tables[id];
		opts.filter = $(elem).val();
		
		var disp_rows = this.getSortedTableRows( opts.id );
		
		// redraw pagination thing
		this.div.find('#st_hinfo_' + opts.id).html(
			this.getTableHeaderInfo(id, disp_rows) 
		);
		
		// redraw rows
		this.div.find('#st_' + opts.id + ' > tbody').html( 
			this.getTableContentHTML( opts.id, disp_rows ) 
		);
	},
	
	getTableHeaderInfo: function(id, disp_rows) {
		// construct HTML for sortable table header info widget
		var opts = this.tables[id];
		var rows = opts.rows;
		var html = '';
		
		if (disp_rows.length < rows.length) {
			html += commify(disp_rows.length) + ' of ' + commify(rows.length) + ' ' + pluralize(opts.item_name, rows.length) + '';
		}
		else {
			html += commify(rows.length) + ' ' + pluralize(opts.item_name, rows.length) + '';
		}
		
		var bold_idx = opts.column_ids.indexOf( opts.sort_by );
		html += ', sorted by ' + opts.column_labels[bold_idx] + '';
		html += ' <i class="fa fa-caret-' + ((opts.sort_dir == 1) ? 'up' : 'down') + '"></i>';
		// html += ((opts.sort_dir == 1) ? ' ascending' : ' descending');
		
		return html;
	},
	
	getTableColumnHTML: function(id) {
		// construct HTML for sortable table column headers (THs)
		var opts = this.tables[id];
		var html = '';
		html += '<tr>';
		
		opts.column_ids.forEach( function(col_id, idx) {
			var col_label = opts.column_labels[idx];
			var classes = ['st_col_header'];
			var icon = '';
			if (col_id == opts.sort_by) {
				classes.push('active');
				icon = ' <i class="fa fa-caret-' + ((opts.sort_dir == 1) ? 'up' : 'down') + '"></i>';
			}
			html += '<th class="' + classes.join(' ') + '" data-id="' + opts.id + '" data-col="' + col_id + '" onMouseUp="$P().toggleTableSort(this)">' + col_label + icon + '</th>';
		});
		
		html += '</tr>';
		return html;
	},
	
	getTableContentHTML: function(id, disp_rows) {
		// construct HTML for sortable table content (rows)
		var opts = this.tables[id];
		var html = '';
		var bold_idx = opts.column_ids.indexOf( opts.sort_by );
		
		for (var idx = 0, len = disp_rows.length; idx < len; idx++) {
			var row = disp_rows[idx];
			var tds = opts.callback(row, idx);
			html += '<tr>';
			for (var idy = 0, ley = tds.length; idy < ley; idy++) {
				html += '<td' + ((bold_idx == idy) ? ' style="font-weight:bold"' : '') + '>' + tds[idy] + '</td>';
			}
			// html += '<td>' + tds.join('</td><td>') + '</td>';
			html += '</tr>';
		} // foreach row
		
		if (!disp_rows.length) {
			html += '<tr><td colspan="' + opts.column_ids.length + '" align="center" style="padding-top:10px; padding-bottom:10px; font-weight:bold;">';
			html += 'No ' + pluralize(opts.item_name) + ' found.';
			html += '</td></tr>';
		}
		
		return html;
	},
	
	toggleTableSort: function(elem) {
		var id = $(elem).data('id');
		var col_id = $(elem).data('col');
		var opts = this.tables[id];
		
		// swap sort dir or change sort column
		if (col_id == opts.sort_by) {
			// swap dir
			opts.sort_dir *= -1;
		}
		else {
			// same sort dir but change column
			opts.sort_by = col_id;
		}
		
		var disp_rows = this.getSortedTableRows( opts.id );
		
		// redraw pagination thing
		this.div.find('#st_hinfo_' + opts.id).html(
			this.getTableHeaderInfo(id, disp_rows) 
		);
		
		// redraw columns
		this.div.find('#st_' + opts.id + ' > thead').html( 
			this.getTableColumnHTML(id) 
		);
		
		// redraw rows
		this.div.find('#st_' + opts.id + ' > tbody').html( 
			this.getTableContentHTML( opts.id, disp_rows ) 
		);
	},
	
	getSortableTable: function(rows, opts, callback) {
		// get HTML for sortable and filterable table
		var self = this;
		var html = '';
		
		// save in page for resort / filtering
		if (!this.tables) this.tables = {};
		opts.rows = rows;
		opts.callback = callback;
		this.tables[ opts.id ] = opts;
		
		var disp_rows = this.getSortedTableRows( opts.id );
		
		// pagination
		html += '<div class="pagination">';
		html += '<table cellspacing="0" cellpadding="0" border="0" width="100%"><tr>';
		
		html += '<td align="left" width="50%" id="st_hinfo_' + opts.id + '">';
		html += this.getTableHeaderInfo( opts.id, disp_rows );
		html += '</td>';
		
		/*html += '<td align="center" width="34%">';
			html += '&nbsp;';
		html += '</td>';*/
		
		html += '<td align="right" width="50%">';
			html += '<div class="sb_header_search_container" style="width:120px">';
				html += '<input type="text" class="sb_header_search" placeholder="Filter" value="' + opts.filter + '" data-id="' + opts.id + '" onKeyUp="$P().applyTableFilter(this)"/>';
				html += '<div class="sb_header_search_icon" onMouseUp="$(this).prev().focus()"><i class="fa fa-search"></i></div>';
			html += '</div>';
		html += '</td>';
		
		html += '</tr></table>';
		html += '</div>';
		
		html += '<div style="margin-top:10px;">';
		html += '<table class="fieldset_table" width="100%" id="st_' + opts.id + '">';
		
		html += '<thead>';
		html += this.getTableColumnHTML( opts.id );
		html += '</thead>';
		
		html += '<tbody>';
		html += this.getTableContentHTML( opts.id, disp_rows );
		html += '</tbody>';
		
		html += '</table>';
		html += '</div>';
		
		return html;
	},
	
	onSecond30: function(dargs) {
		// update graphs on the :30s, but only in realtime view
		var args = this.args;
		
		if (this.args.sub == 'list') {
			// refresh snapshot list every minute
			this.gosub_list(args);
		}
	},
	
	onDeactivate: function() {
		// called when page is deactivated
		// this.div.html( '' );
		return true;
	}
	
} );

Class.subclass( Page.Base, "Page.Login", {	
	
	onInit: function() {
		// called once at page load
		// var html = 'Now is the time (LOGIN)';
		// this.div.html( html );
	},
	
	onActivate: function(args) {
		// page activation
		if (app.user) {
			// user already logged in
			setTimeout( function() { Nav.go(app.navAfterLogin || config.DefaultPage) }, 1 );
			return true;
		}
		else if (args.u && args.h) {
			this.showPasswordResetForm(args);
			return true;
		}
		else if (args.create) {
			this.showCreateAccountForm();
			return true;
		}
		else if (args.recover) {
			this.showRecoverPasswordForm();
			return true;
		}
		
		app.setWindowTitle('Login');
		app.showTabBar(false);
		this.showControls(false);
		
		this.div.css({ 'padding-top':'75px', 'padding-bottom':'75px' });
		var html = '';
		// html += '<iframe name="i_login" id="i_login" src="blank.html" width="1" height="1" style="display:none"></iframe>';
		// html += '<form id="f_login" method="post" action="/api/user/login?format=jshtml&callback=window.parent.%24P%28%29.doFrameLogin" target="i_login">';
		
		html += '<div class="inline_dialog_container">';
			html += '<div class="dialog_title shade-light">User Login</div>';
			html += '<div class="dialog_content">';
				html += '<center><table style="margin:0px;">';
					html += '<tr>';
						html += '<td align="right" class="table_label">Username:</td>';
						html += '<td align="left" class="table_value"><div><input type="text" name="username" id="fe_login_username" size="30" spellcheck="false" value="'+(app.getPref('username') || '')+'"/></div></td>';
					html += '</tr>';
					html += '<tr><td colspan="2"><div class="table_spacer"></div></td></tr>';
					html += '<tr>';
						html += '<td align="right" class="table_label">Password:</td>';
						html += '<td align="left" class="table_value"><div><input type="text" name="password" id="fe_login_password" size="30" spellcheck="false" value=""/>' + app.get_password_toggle_html() + '</div></td>';
					html += '</tr>';
					html += '<tr><td colspan="2"><div class="table_spacer"></div></td></tr>';
				html += '</table></center>';
			html += '</div>';
			
			html += '<div class="dialog_buttons"><center><table><tr>';
				if (config.free_accounts) {
					html += '<td><div class="button" style="width:120px; font-weight:normal;" onMouseUp="$P().navCreateAccount()">Create Account...</div></td>';
					html += '<td width="20">&nbsp;</td>';
				}
				html += '<td><div class="button" style="width:120px; font-weight:normal;" onMouseUp="$P().navPasswordRecovery()">Forgot Password...</div></td>';
				html += '<td width="20">&nbsp;</td>';
				html += '<td><div class="button" style="width:120px;" onMouseUp="$P().doLogin()"><i class="fa fa-sign-in">&nbsp;&nbsp;</i>Login</div></td>';
			html += '</tr></table></center></div>';
		html += '</div>';
		
		// html += '<input type="submit" value="Login" style="position:absolute; left:-9999px; top:0px;">';
		html += '</form>';
		this.div.html( html );
		
		setTimeout( function() {
			$( app.getPref('username') ? '#fe_login_password' : '#fe_login_username' ).focus();
			
			 $('#fe_login_username, #fe_login_password').keypress( function(event) {
				if (event.keyCode == '13') { // enter key
					event.preventDefault();
					$P().doLogin();
				}
			} ); 
			
		}, 1 );
		
		return true;
	},
	
	/*doLoginFormSubmit: function() {
		// force login form to submit
		$('#f_login')[0].submit();
	},
	
	doFrameLogin: function(resp) {
		// login from IFRAME redirect
		// alert("GOT HERE FROM IFRAME " + JSON.stringify(resp));
		this.tempFrameResp = JSON.parse( JSON.stringify(resp) );
		setTimeout( '$P().doFrameLogin2()', 1 );
	},
	
	doFrameLogin2: function() {
		// login from IFRAME redirect
		var resp = this.tempFrameResp;
		delete this.tempFrameResp;
		
		Debug.trace("IFRAME Response: " + JSON.stringify(resp));
		
		if (resp.code) {
			return app.doError( resp.description );
		}
		
		Debug.trace("IFRAME User Login: " + resp.username + ": " + resp.session_id);
		
		app.clearError();
		app.hideProgress();
		app.doUserLogin( resp );
		
		Nav.go( app.navAfterLogin || config.DefaultPage );
		// alert("GOT HERE: " + (app.navAfterLogin || config.DefaultPage) );
	},*/
	
	 doLogin: function() {
		// attempt to log user in
		var username = $('#fe_login_username').val().toLowerCase();
		var password = $('#fe_login_password').val();
		
		if (username && password) {
			app.showProgress(1.0, "Logging in...");
			
			app.api.post( 'user/login', {
				username: username,
				password: password
			}, 
			function(resp, tx) {
				Debug.trace("User Login: " + username + ": " + resp.session_id);
				
				app.hideProgress();
				app.doUserLogin( resp );
				
				Nav.go( app.navAfterLogin || config.DefaultPage );
			} ); // post
		}
	}, 
	
	cancel: function() {
		// return to login page
		app.clearError();
		Nav.go('Login', true);
	},
	
	navCreateAccount: function() {
		// nav to create account form
		app.clearError();
		Nav.go('Login?create=1', true);
	},
	
	showCreateAccountForm: function() {
		// allow user to create a new account
		app.setWindowTitle('Create Account');
		app.showTabBar(false);
		
		this.div.css({ 'padding-top':'75px', 'padding-bottom':'75px' });
		var html = '';
		
		html += '<div class="inline_dialog_container">';
			html += '<div class="dialog_title shade-light">Create Account</div>';
			html += '<div class="dialog_content">';
				html += '<center><table style="margin:0px;">';
				
				// username
				html += get_form_table_row( 'Username:', 
					'<table cellspacing="0" cellpadding="0"><tr>' + 
						'<td><input type="text" id="fe_ca_username" size="20" style="font-size:14px;" value="" spellcheck="false" onChange="$P().checkUserExists(\'ca\')"/></td>' + 
						'<td><div id="d_ca_valid" style="margin-left:5px; font-weight:bold;"></div></td>' + 
					'</tr></table>'
				);
				html += get_form_table_caption('Choose a unique alphanumeric username for your account.') + 
				get_form_table_spacer() + 
				
				// password
				get_form_table_row('Password:', '<input type="text" id="fe_ca_password" size="30" value="" spellcheck="false"/>' + app.get_password_toggle_html()) + 
				get_form_table_caption('Enter a secure password that you will not forget.') + 
				get_form_table_spacer() + 
				
				// full name
				get_form_table_row('Full Name:', '<input type="text" id="fe_ca_fullname" size="30" value="" spellcheck="false"/>') + 
				get_form_table_caption('This is used for display purposes only.') + 
				get_form_table_spacer() + 
				
				// email
				get_form_table_row('Email Address:', '<input type="text" id="fe_ca_email" size="30" value="" spellcheck="false"/>') + 
				get_form_table_caption('This is used only to recover your password should you lose it.');
					
				html += '</table></center>';
			html += '</div>';
			
			html += '<div class="dialog_buttons"><center><table><tr>';
				html += '<td><div class="button" style="width:120px; font-weight:normal;" onMouseUp="$P().cancel()">Cancel</div></td>';
				html += '<td width="50">&nbsp;</td>';
				html += '<td><div class="button" style="width:120px;" onMouseUp="$P().doCreateAccount()"><i class="fa fa-user-plus">&nbsp;&nbsp;</i>Create</div></td>';
			html += '</tr></table></center></div>';
		html += '</div>';
		
		this.div.html( html );
		
		setTimeout( function() {
			$( '#fe_ca_username' ).focus();
		}, 1 );
	},
	
	doCreateAccount: function(force) {
		// actually create account
		app.clearError();
		
		var username = trim($('#fe_ca_username').val().toLowerCase());
		var email = trim($('#fe_ca_email').val());
		var full_name = trim($('#fe_ca_fullname').val());
		var password = trim($('#fe_ca_password').val());
		
		if (!username.length) {
			return app.badField('#fe_ca_username', "Please enter a username for your account.");
		}
		if (!username.match(/^[\w\-\.]+$/)) {
			return app.badField('#fe_ca_username', "Please make sure your username contains only alphanumerics, dashes and periods.");
		}
		if (!email.length) {
			return app.badField('#fe_ca_email', "Please enter an e-mail address where you can be reached.");
		}
		if (!email.match(/^\S+\@\S+$/)) {
			return app.badField('#fe_ca_email', "The e-mail address you entered does not appear to be correct.");
		}
		if (!full_name.length) {
			return app.badField('#fe_ca_fullname', "Please enter your first and last names. These are used only for display purposes.");
		}
		if (!password.length) {
			return app.badField('#fe_ca_password', "Please enter a secure password to protect your account.");
		}
		
		Dialog.hide();
		app.showProgress( 1.0, "Creating account..." );
		
		app.api.post( 'user/create', {
			username: username,
			email: email,
			password: password,
			full_name: full_name
		}, 
		function(resp, tx) {
			app.hideProgress();
			app.showMessage('success', "Account created successfully.");
			
			app.setPref('username', username);
			Nav.go( 'Login', true );
		} ); // api.post
	},
	
	navPasswordRecovery: function() {
		// nav to recover password form
		app.clearError();
		Nav.go('Login?recover=1', true);
	},
	
	showRecoverPasswordForm: function() {
		// allow user to create a new account
		app.setWindowTitle('Forgot Password');
		app.showTabBar(false);
		
		this.div.css({ 'padding-top':'75px', 'padding-bottom':'75px' });
		var html = '';
		
		html += '<div class="inline_dialog_container">';
			html += '<div class="dialog_title shade-light">Forgot Password</div>';
			html += '<div class="dialog_content">';
				html += '<center><table style="margin:0px;">';
				
				html += get_form_table_row('Username:', '<input type="text" id="fe_pr_username" size="30" value="" spellcheck="false"/>') + 
				get_form_table_spacer() + 
				get_form_table_row('Email Address:', '<input type="text" id="fe_pr_email" size="30" value="" spellcheck="false"/>');
				
				html += '</table></center>';
				
				html += '<div class="caption" style="margin-top:15px;">Please enter the username and e-mail address associated with your account, and we will send you instructions for resetting your password.</div>';
				
			html += '</div>';
			
			html += '<div class="dialog_buttons"><center><table><tr>';
				html += '<td><div class="button" style="width:120px; font-weight:normal;" onMouseUp="$P().cancel()">Cancel</div></td>';
				html += '<td width="50">&nbsp;</td>';
				html += '<td><div class="button" style="width:120px;" onMouseUp="$P().doSendRecoveryEmail()"><i class="fa fa-envelope-o">&nbsp;&nbsp;</i>Send Email</div></td>';
			html += '</tr></table></center></div>';
		html += '</div>';
		
		this.div.html( html );
		
		setTimeout( function() { 
			$('#fe_pr_username, #fe_pr_email').keypress( function(event) {
				if (event.keyCode == '13') { // enter key
					event.preventDefault();
					$P().doSendEmail();
				}
			} );
			$( '#fe_pr_username' ).focus();
		}, 1 );
	},
	
	doSendRecoveryEmail: function() {
		// send password recovery e-mail
		app.clearError();
		
		var username = trim($('#fe_pr_username').val()).toLowerCase();
		var email = trim($('#fe_pr_email').val());
		
		if (username.match(/^\w+$/)) {
			if (email.match(/.+\@.+/)) {
				Dialog.hide();
				app.showProgress( 1.0, "Sending e-mail..." );
				app.api.post( 'user/forgot_password', {
					username: username,
					email: email
				}, 
				function(resp, tx) {
					app.hideProgress();
					app.showMessage('success', "Password reset instructions sent successfully.");
					Nav.go('Login', true);
				} ); // api.post
			} // good address
			else app.badField('#fe_pr_email', "The e-mail address you entered does not appear to be correct.");
		} // good username
		else app.badField('#fe_pr_username', "The username you entered does not appear to be correct.");
	},
	
	showPasswordResetForm: function(args) {
		// show password reset form
		this.recoveryKey = args.h;
		
		app.setWindowTitle('Reset Password');
		app.showTabBar(false);
		
		this.div.css({ 'padding-top':'75px', 'padding-bottom':'75px' });
		var html = '';
		
		html += '<div class="inline_dialog_container">';
			html += '<div class="dialog_title shade-light">Reset Password</div>';
			html += '<div class="dialog_content">';
				html += '<center><table style="margin:0px;">';
					html += '<tr>';
						html += '<td align="right" class="table_label">Username:</td>';
						html += '<td align="left" class="table_value"><div><input type="text" name="username" id="fe_reset_username" size="30" spellcheck="false" value="'+args.u+'" disabled="disabled"/></div></td>';
					html += '</tr>';
					html += '<tr><td colspan="2"><div class="table_spacer"></div></td></tr>';
					html += '<tr>';
						html += '<td align="right" class="table_label">New Password:</td>';
						html += '<td align="left" class="table_value"><div><input type="text" name="password" id="fe_reset_password" size="30" spellcheck="false" value=""/>' + app.get_password_toggle_html() + '</div></td>';
					html += '</tr>';
					html += '<tr><td colspan="2"><div class="table_spacer"></div></td></tr>';
				html += '</table></center>';
			html += '</div>';
			
			html += '<div class="dialog_buttons"><center><table><tr>';
				html += '<td><div class="button" style="width:130px;" onMouseUp="$P().doResetPassword()"><i class="fa fa-key">&nbsp;&nbsp;</i>Reset Password</div></td>';
			html += '</tr></table></center></div>';
		html += '</div>';
		
		this.div.html( html );
		
		setTimeout( function() {
			$( '#fe_reset_password' ).focus();
			$('#fe_reset_password').keypress( function(event) {
				if (event.keyCode == '13') { // enter key
					event.preventDefault();
					$P().doResetPassword();
				}
			} );
		}, 1 );
	},
	
	doResetPassword: function(force) {
		// reset password now
		var username = $('#fe_reset_username').val().toLowerCase();
		var new_password = $('#fe_reset_password').val();
		var recovery_key = this.recoveryKey;
		
		if (username && new_password) {
			
			app.showProgress(1.0, "Resetting password...");
			
			app.api.post( 'user/reset_password', {
				username: username,
				key: recovery_key,
				new_password: new_password
			}, 
			function(resp, tx) {
				Debug.trace("User password was reset: " + username);
				
				app.hideProgress();
				app.setPref('username', username);
				
				Nav.go( 'Login', true );
				
				setTimeout( function() {
					app.showMessage('success', "Your password was reset successfully.");
				}, 100 );
			} ); // post
		}
	},
	
	onDeactivate: function() {
		// called when page is deactivated
		this.div.html( '' );
		return true;
	}
	
} );

Class.subclass( Page.Base, "Page.MyAccount", {	
		
	onInit: function() {
		// called once at page load
		var html = '';
		this.div.html( html );
	},
	
	onActivate: function(args) {
		// page activation
		if (!this.requireLogin(args)) return true;
		
		if (!args) args = {};
		this.args = args;
		
		app.setWindowTitle('My Account');
		app.showTabBar(true);
		this.showControls(false);
		
		this.receive_user({ user: app.user });
		
		return true;
	},
	
	receive_user: function(resp, tx) {
		var self = this;
		var html = '';
		var user = resp.user;
				
		html += '<div style="padding:50px 20px 50px 20px">';
		html += '<center>';
		
		html += '<table><tr>';
			html += '<td valign="top" style="vertical-align:top">';
			
		html += '<table style="margin:0;">';
		
		// user id
		html += get_form_table_row( 'Username', '<div style="font-size: 14px;"><b>' + app.username + '</b></div>' );
		html += get_form_table_caption( "Your username cannot be changed." );
		html += get_form_table_spacer();
		
		// full name
		html += get_form_table_row( 'Full Name', '<input type="text" id="fe_ma_fullname" size="30" value="'+escape_text_field_value(user.full_name)+'"/>' );
		html += get_form_table_caption( "Your first and last names, used for display purposes only.");
		html += get_form_table_spacer();
		
		// email
		html += get_form_table_row( 'Email Address', '<input type="text" id="fe_ma_email" size="30" value="'+escape_text_field_value(user.email)+'"/>' );
		html += get_form_table_caption( "This is used to generate your profile pic, and to<br/>recover your password if you forget it." );
		html += get_form_table_spacer();
		
		// current password
		html += get_form_table_row( 'Current Password', '<input type="text" id="fe_ma_old_password" size="30" value=""/>' + app.get_password_toggle_html() );
		html += get_form_table_caption( "Enter your current account password to make changes." );
		html += get_form_table_spacer();
		
		// reset password
		html += get_form_table_row( 'New Password', '<input type="text" id="fe_ma_new_password" size="30" value=""/>' + app.get_password_toggle_html() );
		html += get_form_table_caption( "If you need to change your password, enter the new one here." );
		html += get_form_table_spacer();
		
		html += '<tr><td colspan="2" align="center">';
			html += '<div style="height:30px;"></div>';
			
			html += '<table><tr>';
				html += '<td><div class="button" style="width:130px; font-weight:normal;" onMouseUp="$P().show_delete_account_dialog()">Delete Account...</div></td>';
				html += '<td width="80">&nbsp;</td>';
				html += '<td><div class="button" style="width:130px;" onMouseUp="$P().save_changes()"><i class="fa fa-floppy-o">&nbsp;&nbsp;</i>Save Changes</div></td>';
			html += '</tr></table>';
			
		html += '</td></tr>';
		
		html += '</table>';
		html += '</center>';
		
		html += '</td>';
			html += '<td valign="top" align="left" style="vertical-align:top; text-align:left;">';
				// gravar profile image and edit button
				html += '<fieldset style="width:150px; margin-left:40px; border:1px solid rgba(128, 128, 128, 0.25); box-shadow:none;"><legend>Profile Picture</legend>';
				if (app.config.external_users) {
					html += '<div id="d_ma_image" style="width:128px; height:128px; margin:5px auto 0 auto; background-image:url('+app.getUserAvatarURL(128)+'); cursor:default;"></div>';
				}
				else {
					html += '<div id="d_ma_image" style="width:128px; height:128px; margin:5px auto 0 auto; background-image:url('+app.getUserAvatarURL(128)+'); cursor:pointer;" onMouseUp="$P().edit_gravatar()"></div>';
					html += '<div class="button mini" style="margin:10px auto 5px auto;" onMouseUp="$P().edit_gravatar()">Edit Image...</div>';
					html += '<div style="font-size:11px; color:#888; text-align:center; margin-bottom:5px;">Image services provided by <a href="https://en.gravatar.com/connect/" target="_blank">Gravatar.com</a>.</div>';
				}
				html += '</fieldset>';
			html += '</td>';
		html += '</tr></table>';
		
		html += '</div>'; // table wrapper div
				
		this.div.html( html );
		
		setTimeout( function() {
			if (app.config.external_users) {
				app.showMessage('warning', "Users are managed by an external system, so you cannot make changes here.");
				self.div.find('input').prop('disabled', true);
			}
		}, 1 );
	},
	
	edit_gravatar: function() {
		// edit profile pic at gravatar.com
		window.open( 'https://en.gravatar.com/connect/' );
	},
	
	save_changes: function(force) {
		// save changes to user info
		app.clearError();
		if (app.config.external_users) {
			return app.doError("Users are managed by an external system, so you cannot make changes here.");
		}
		if (!$('#fe_ma_old_password').val()) return app.badField('#fe_ma_old_password', "Please enter your current account password to make changes.");
		
		app.showProgress( 1.0, "Saving account..." );
		
		app.api.post( 'user/update', {
			username: app.username,
			full_name: trim($('#fe_ma_fullname').val()),
			email: trim($('#fe_ma_email').val()),
			old_password: $('#fe_ma_old_password').val(),
			new_password: $('#fe_ma_new_password').val()
		}, 
		function(resp) {
			// save complete
			app.hideProgress();
			app.showMessage('success', "Your account settings were updated successfully.");
			
			$('#fe_ma_old_password').val('');
			$('#fe_ma_new_password').val('');
			
			app.user = resp.user;
			app.updateHeaderInfo();
			
			$('#d_ma_image').css( 'background-image', 'url('+app.getUserAvatarURL(128)+')' );
		} );
	},
	
	show_delete_account_dialog: function() {
		// show dialog confirming account delete action
		var self = this;
		
		app.clearError();
		if (app.config.external_users) {
			return app.doError("Users are managed by an external system, so you cannot make changes here.");
		}
		if (!$('#fe_ma_old_password').val()) return app.badField('#fe_ma_old_password', "Please enter your current account password.");
		
		app.confirm( "Delete My Account", "Are you sure you want to <b>permanently delete</b> your user account?  There is no way to undo this action, and no way to recover your data.", "Delete", function(result) {
			if (result) {
				app.showProgress( 1.0, "Deleting Account..." );
				app.api.post( 'user/delete', {
					username: app.username,
					password: $('#fe_ma_old_password').val()
				}, 
				function(resp) {
					// finished deleting, immediately log user out
					app.doUserLogout();
				} );
			}
		} );
	},
	
	onDeactivate: function() {
		// called when page is deactivated
		// this.div.html( '' );
		return true;
	}
	
} );

Class.subclass( Page.Base, "Page.Admin", {	
	
	usernames: null,
	default_sub: 'activity',
	
	onInit: function() {
		// called once at page load
		var html = '';
		this.div.html( html );
	},
	
	onActivate: function(args) {
		// page activation
		if (!this.requireLogin(args)) return true;
		
		if (!args) args = {};
		if (!args.sub) args.sub = this.default_sub;
		this.args = args;
		
		app.showTabBar(true);
		this.showControls(false);
		this.tab[0]._page_id = Nav.currentAnchor();
		
		this.div.addClass('loading');
		this['gosub_'+args.sub](args);
		
		return true;
	},
	
	onDeactivate: function() {
		// called when page is deactivated
		// this.div.html( '' );
		return true;
	}
	
} );

// Admin Page -- Users

Class.add( Page.Admin, {
	
	gosub_users: function(args) {
		// show user list
		app.setWindowTitle( "User List" );
		this.div.addClass('loading');
		if (!args.offset) args.offset = 0;
		if (!args.limit) args.limit = 25;
		app.api.post( 'user/admin_get_users', copy_object(args), this.receive_users.bind(this) );
	},
	
	receive_users: function(resp) {
		// receive page of users from server, render it
		this.lastUsersResp = resp;
		
		var html = '';
		this.div.removeClass('loading');
		
		var size = get_inner_window_size();
		var col_width = Math.floor( ((size.width * 0.9) + 200) / 8 );
		
		this.users = [];
		if (resp.rows) this.users = resp.rows;
		
		html += this.getSidebarTabs( 'users',
			[
				['activity', "Activity"],
				['alerts', "Alerts"],
				['api_keys', "API Keys"],
				['commands', "Commands"],
				['groups', "Groups"],
				['monitors', "Monitors"],
				['users', "Users"]
			]
		);
		
		var cols = ['Username', 'Full Name', 'Email Address', 'Status', 'Type', 'Created', 'Actions'];
		
		// html += '<div style="padding:5px 15px 15px 15px;">';
		html += '<div style="padding:20px 20px 30px 20px">';
		
		html += '<div class="subtitle">';
			html += 'User Accounts';
			// html += '<div class="subtitle_widget"><span class="link" onMouseUp="$P().refresh_user_list()"><b>Refresh</b></span></div>';
			html += '<div class="subtitle_widget"><i class="fa fa-search">&nbsp;</i><input type="text" id="fe_ul_search" size="15" placeholder="Find username..." style="border:0px;"/></div>';
			html += '<div class="clear"></div>';
		html += '</div>';
		
		var self = this;
		html += this.getPaginatedTable( resp, cols, 'user', function(user, idx) {
			var actions = [
				'<span class="link" onMouseUp="$P().edit_user('+idx+')"><b>Edit</b></span>',
				'<span class="link" onMouseUp="$P().delete_user('+idx+')"><b>Delete</b></span>'
			];
			return [
				'<div class="td_big">' + self.getNiceUsername(user, true, col_width) + '</div>',
				'<div class="ellip" style="max-width:'+col_width+'px;">' + user.full_name + '</div>',
				'<div class="ellip" style="max-width:'+col_width+'px;"><a href="mailto:'+user.email+'">'+user.email+'</a></div>',
				user.active ? '<span class="color_label green"><i class="fa fa-check">&nbsp;</i>Active</span>' : '<span class="color_label red"><i class="fa fa-warning">&nbsp;</i>Suspended</span>',
				user.privileges.admin ? '<span class="color_label purple"><i class="fa fa-lock">&nbsp;</i>Admin</span>' : '<span class="color_label gray">Standard</span>',
				'<span title="'+get_nice_date_time(user.created, true)+'">'+get_nice_date(user.created, true)+'</span>',
				actions.join(' | ')
			];
		} );
		
		html += '<div style="height:30px;"></div>';
		html += '<center><table><tr>';
			html += '<td><div class="button" style="width:130px;" onMouseUp="$P().edit_user(-1)"><i class="fa fa-user-plus">&nbsp;&nbsp;</i>Add User...</div></td>';
		html += '</tr></table></center>';
		
		html += '</div>'; // padding
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
		
		setTimeout( function() {
			$('#fe_ul_search').keypress( function(event) {
				if (event.keyCode == '13') { // enter key
					event.preventDefault();
					$P().do_user_search( $('#fe_ul_search').val() );
				}
			} )
			.blur( function() { app.hideMessage(250); } )
			.keydown( function() { app.hideMessage(); } );
		}, 1 );
	},
	
	do_user_search: function(username) {
		// see if user exists, edit if so
		app.api.post( 'user/admin_get_user', { username: username }, 
			function(resp) {
				Nav.go('Admin?sub=edit_user&username=' + username);
			},
			function(resp) {
				app.doError("User not found: " + username, 10);
			}
		);
	},
	
	edit_user: function(idx) {
		// jump to edit sub
		if (idx > -1) Nav.go( '#Admin?sub=edit_user&username=' + this.users[idx].username );
		else if (app.config.external_users) {
			app.doError("Users are managed by an external system, so you cannot add users from here.");
		}
		else Nav.go( '#Admin?sub=new_user' );
	},
	
	delete_user: function(idx) {
		// delete user from search results
		this.user = this.users[idx];
		this.show_delete_account_dialog();
	},
	
	gosub_new_user: function(args) {
		// create new user
		var html = '';
		app.setWindowTitle( "Add New User" );
		this.div.removeClass('loading');
		
		html += this.getSidebarTabs( 'new_user',
			[
				['activity', "Activity"],
				['alerts', "Alerts"],
				['api_keys', "API Keys"],
				['commands', "Commands"],
				['groups', "Groups"],
				['monitors', "Monitors"],
				['users', "Users"],
				['new_user', "Add New User"]
			]
		);
		
		html += '<div style="padding:20px;"><div class="subtitle">Add New User</div></div>';
		
		html += '<div style="padding:0px 20px 50px 20px">';
		html += '<center><table style="margin:0;">';
		
		this.user = { 
			privileges: copy_object( config.default_privileges )
		};
		
		html += this.get_user_edit_html();
		
		// notify user
		html += get_form_table_row( 'Notify', '<input type="checkbox" id="fe_eu_send_email" value="1" checked="checked"/><label for="fe_eu_send_email">Send Welcome Email</label>' );
		html += get_form_table_caption( "Select notification options for the new user." );
		html += get_form_table_spacer();
		
		// buttons at bottom
		html += '<tr><td colspan="2" align="center">';
			html += '<div style="height:30px;"></div>';
			
			html += '<table><tr>';
				html += '<td><div class="button" style="width:120px; font-weight:normal;" onMouseUp="$P().cancel_user_edit()">Cancel</div></td>';
				html += '<td width="50">&nbsp;</td>';
				if (config.debug) {
					html += '<td><div class="button" style="width:120px; font-weight:normal;" onMouseUp="$P().populate_random_user()">Randomize...</div></td>';
					html += '<td width="50">&nbsp;</td>';
				}
				html += '<td><div class="button" style="width:120px;" onMouseUp="$P().do_new_user()"><i class="fa fa-user-plus">&nbsp;&nbsp;</i>Add User</div></td>';
			html += '</tr></table>';
			
		html += '</td></tr>';
		
		html += '</table></center>';
		html += '</div>'; // table wrapper div
		
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
		
		setTimeout( function() {
			$('#fe_eu_username').focus();
		}, 1 );
	},
	
	cancel_user_edit: function() {
		// cancel editing user and return to list
		Nav.go( 'Admin?sub=users' );
	},
	
	populate_random_user: function() {
		// grab random user data (for testing only)
		var self = this;
		
		$.ajax({
			url: 'https://api.randomuser.me/',
			dataType: 'json',
			success: function(data){
				// console.log(data);
				if (data.results && data.results[0] && data.results[0]) {
					var user = data.results[0];
					$('#fe_eu_username').val( user.login.username );
					$('#fe_eu_email').val( user.email );
					$('#fe_eu_fullname').val( ucfirst(user.name.first) + ' ' + ucfirst(user.name.last) );
					$('#fe_eu_send_email').prop( 'checked', false );
					self.generate_password();
					self.checkUserExists('eu');
				}
			}
		});
	},
	
	do_new_user: function(force) {
		// create new user
		app.clearError();
		var user = this.get_user_form_json();
		if (!user) return; // error
		
		if (!user.username.length) {
			return app.badField('#fe_eu_username', "Please enter a username for the new account.");
		}
		if (!user.username.match(/^[\w\-\.]+$/)) {
			return app.badField('#fe_eu_username', "Please make sure the username contains only alphanumerics, periods and dashes.");
		}
		if (!user.email.length) {
			return app.badField('#fe_eu_email', "Please enter an e-mail address where the user can be reached.");
		}
		if (!user.email.match(/^\S+\@\S+$/)) {
			return app.badField('#fe_eu_email', "The e-mail address you entered does not appear to be correct.");
		}
		if (!user.full_name.length) {
			return app.badField('#fe_eu_fullname', "Please enter the user's first and last names.");
		}
		if (!user.password.length) {
			return app.badField('#fe_eu_password', "Please enter a secure password to protect the account.");
		}
		
		user.send_email = $('#fe_eu_send_email').is(':checked') ? 1 : 0;
		
		this.user = user;
		
		app.showProgress( 1.0, "Creating user..." );
		app.api.post( 'user/admin_create', user, this.new_user_finish.bind(this) );
	},
	
	new_user_finish: function(resp) {
		// new user created successfully
		app.hideProgress();
		
		// Nav.go('Admin?sub=edit_user&username=' + this.user.username);
		Nav.go('Admin?sub=users');
		
		setTimeout( function() {
			app.showMessage('success', "The new user account was created successfully.");
		}, 150 );
	},
	
	gosub_edit_user: function(args) {
		// edit user subpage
		this.div.addClass('loading');
		app.api.post( 'user/admin_get_user', { username: args.username }, this.receive_user.bind(this) );
	},
	
	receive_user: function(resp) {
		// edit existing user
		var html = '';
		app.setWindowTitle( "Editing User \"" + (this.args.username) + "\"" );
		this.div.removeClass('loading');
		
		html += this.getSidebarTabs( 'edit_user',
			[	
				['activity', "Activity"],
				['alerts', "Alerts"],
				['api_keys', "API Keys"],
				['commands', "Commands"],
				['groups', "Groups"],
				['monitors', "Monitors"],
				['users', "Users"],
				['edit_user', "Edit User"]
			]
		);
		
		html += '<div style="padding:20px;"><div class="subtitle">Editing User &ldquo;' + (this.args.username) + '&rdquo;</div></div>';
		
		html += '<div style="padding:0px 20px 50px 20px">';
		html += '<center>';
		html += '<table style="margin:0;">';
		
		this.user = resp.user;
		
		html += this.get_user_edit_html();
		
		html += '<tr><td colspan="2" align="center">';
			html += '<div style="height:30px;"></div>';
			
			html += '<table><tr>';
				html += '<td><div class="button" style="width:130px; font-weight:normal;" onMouseUp="$P().cancel_user_edit()">Cancel</div></td>';
				html += '<td width="50">&nbsp;</td>';
				html += '<td><div class="button" style="width:130px; font-weight:normal;" onMouseUp="$P().show_delete_account_dialog()">Delete Account...</div></td>';
				html += '<td width="50">&nbsp;</td>';
				html += '<td><div class="button" style="width:130px;" onMouseUp="$P().do_save_user()"><i class="fa fa-floppy-o">&nbsp;&nbsp;</i>Save Changes</div></td>';
			html += '</tr></table>';
			
		html += '</td></tr>';
		
		html += '</table>';
		html += '</center>';
		html += '</div>'; // table wrapper div
		
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
		
		setTimeout( function() {
			$('#fe_eu_username').attr('disabled', true);
			
			if (app.config.external_users) {
				app.showMessage('warning', "Users are managed by an external system, so making changes here may have little effect.");
				// self.div.find('input').prop('disabled', true);
			}
		}, 1 );
	},
	
	do_save_user: function() {
		// create new user
		app.clearError();
		var user = this.get_user_form_json();
		if (!user) return; // error
		
		// if changing password, give server a hint
		if (user.password) {
			user.new_password = user.password;
			delete user.password;
		}
		
		this.user = user;
		
		app.showProgress( 1.0, "Saving user account..." );
		app.api.post( 'user/admin_update', user, this.save_user_finish.bind(this) );
	},
	
	save_user_finish: function(resp, tx) {
		// new user created successfully
		app.hideProgress();
		app.showMessage('success', "The user was saved successfully.");
		window.scrollTo( 0, 0 );
		
		// if we edited ourself, update header
		if (this.args.username == app.username) {
			app.user = resp.user;
			app.updateHeaderInfo();
		}
		
		$('#fe_eu_password').val('');
	},
	
	show_delete_account_dialog: function() {
		// show dialog confirming account delete action
		var self = this;
		
		var msg = "Are you sure you want to <b>permanently delete</b> the user account \""+this.user.username+"\"?  There is no way to undo this action, and no way to recover the data.";
		
		if (app.config.external_users) {
			msg = "Are you sure you want to delete the user account \""+this.user.username+"\"?  Users are managed by an external system, so this will have little effect here.";
			// return app.doError("Users are managed by an external system, so you cannot make changes here.");
		}
		
		app.confirm( '<span style="color:red">Delete Account</span>', msg, 'Delete', function(result) {
			if (result) {
				app.showProgress( 1.0, "Deleting Account..." );
				app.api.post( 'user/admin_delete', {
					username: self.user.username
				}, self.delete_user_finish.bind(self) );
			}
		} );
	},
	
	delete_user_finish: function(resp, tx) {
		// finished deleting, immediately log user out
		var self = this;
		app.hideProgress();
		
		Nav.go('Admin?sub=users', 'force');
		
		setTimeout( function() {
			app.showMessage('success', "The user account '"+self.user.username+"' was deleted successfully.");
		}, 150 );
	},
	
	get_user_edit_html: function() {
		// get html for editing a user (or creating a new one)
		var html = '';
		var user = this.user;
		
		// user id
		html += get_form_table_row( 'Username', 
			'<table cellspacing="0" cellpadding="0"><tr>' + 
				'<td><input type="text" id="fe_eu_username" size="20" style="font-size:14px;" value="'+escape_text_field_value(user.username)+'" spellcheck="false" onChange="$P().checkUserExists(\'eu\')"/></td>' + 
				'<td><div id="d_eu_valid" style="margin-left:5px; font-weight:bold;"></div></td>' + 
			'</tr></table>'
		);
		html += get_form_table_caption( "Enter the username which identifies this account.  Once entered, it cannot be changed. " );
		html += get_form_table_spacer();
		
		// account status
		html += get_form_table_row( 'Account Status', '<select id="fe_eu_status">' + render_menu_options([[1,'Active'], [0,'Suspended']], user.active) + '</select>' );
		html += get_form_table_caption( "'Suspended' means that the account remains in the system, but the user cannot log in." );
		html += get_form_table_spacer();
		
		// full name
		html += get_form_table_row( 'Full Name', '<input type="text" id="fe_eu_fullname" size="30" value="'+escape_text_field_value(user.full_name)+'" spellcheck="false"/>' );
		html += get_form_table_caption( "User's first and last name.  They will not be shared with anyone outside the server.");
		html += get_form_table_spacer();
		
		// email
		html += get_form_table_row( 'Email Address', '<input type="text" id="fe_eu_email" size="30" value="'+escape_text_field_value(user.email)+'" spellcheck="false"/>' );
		html += get_form_table_caption( "This can be used to recover the password if the user forgets.  It will not be shared with anyone outside the server." );
		html += get_form_table_spacer();
		
		// password
		html += get_form_table_row( user.password ? 'Change Password' : 'Password', '<input type="text" id="fe_eu_password" size="20" value=""/>&nbsp;<span class="link addme" onMouseUp="$P().generate_password()">&laquo; Generate Random</span>' );
		html += get_form_table_caption( user.password ? "Optionally enter a new password here to reset it.  Please make it secure." : "Enter a password for the account.  Please make it secure." );
		html += get_form_table_spacer();
		
		// privilege list
		var priv_html = '';
		var user_is_admin = !!user.privileges.admin;
		
		for (var idx = 0, len = config.privilege_list.length; idx < len; idx++) {
			var priv = config.privilege_list[idx];
			var has_priv = !!user.privileges[ priv.id ];
			var priv_visible = (priv.id == 'admin') || !user_is_admin;
			var priv_class = (priv.id == 'admin') ? 'priv_group_admin' : 'priv_group_other';
			
			priv_html += '<div class="'+priv_class+'" style="margin-top:4px; margin-bottom:4px; '+(priv_visible ? '' : 'display:none;')+'">';
			priv_html += '<input type="checkbox" id="fe_eu_priv_'+priv.id+'" value="1" ' + 
				(has_priv ? 'checked="checked" ' : '') + ((priv.id == 'admin') ? 'onChange="$P().change_admin_checkbox()"' : '') + '>';
			priv_html += '<label for="fe_eu_priv_'+priv.id+'">'+priv.title+'</label>';
			priv_html += '</div>';
		}
		
		html += get_form_table_row( 'Privileges', priv_html );
		html += get_form_table_caption( "Select which privileges the user account should have. Administrators have all privileges." );
		html += get_form_table_spacer();
		
		return html;
	},
	
	change_admin_checkbox: function() {
		// toggle admin checkbox
		var is_checked = $('#fe_eu_priv_admin').is(':checked');
		if (is_checked) this.div.find('div.priv_group_other').hide(250);
		else this.div.find('div.priv_group_other').show(250);
	},
	
	get_user_form_json: function() {
		// get user elements from form, used for new or edit
		var user = {
			username: trim($('#fe_eu_username').val().toLowerCase()),
			active: parseInt( $('#fe_eu_status').val() ),
			full_name: trim($('#fe_eu_fullname').val()),
			email: trim($('#fe_eu_email').val()),
			password: $('#fe_eu_password').val(),
			privileges: {}
		};
		
		for (var idx = 0, len = config.privilege_list.length; idx < len; idx++) {
			var priv = config.privilege_list[idx];
			user.privileges[ priv.id ] = $('#fe_eu_priv_'+priv.id).is(':checked') ? 1 : 0;
		}
		
		return user;
	},
	
	generate_password: function() {
		// generate random-ish password
		$('#fe_eu_password').val( b64_md5(get_unique_id()).substring(0, 8) );
	}
	
});

// Admin Page -- API Keys

Class.add( Page.Admin, {
	
	gosub_api_keys: function(args) {
		// show API Key list
		app.setWindowTitle( "API Keys" );
		this.div.addClass('loading');
		app.api.post( 'app/get_api_keys', copy_object(args), this.receive_keys.bind(this) );
	},
	
	receive_keys: function(resp) {
		// receive all API Keys from server, render them sorted
		this.lastAPIKeysResp = resp;
		
		var html = '';
		this.div.removeClass('loading');
		
		var size = get_inner_window_size();
		var col_width = Math.floor( ((size.width * 0.9) + 200) / 7 );
		
		if (!resp.rows) resp.rows = [];
		
		// sort by title ascending
		this.api_keys = resp.rows.sort( function(a, b) {
			return a.title.toLowerCase().localeCompare( b.title.toLowerCase() );
		} );
		
		html += this.getSidebarTabs( 'api_keys',
			[
				['activity', "Activity"],
				['alerts', "Alerts"],
				['api_keys', "API Keys"],
				['commands', "Commands"],
				['groups', "Groups"],
				['monitors', "Monitors"],
				['users', "Users"]
			]
		);
		
		var cols = ['App Title', 'API Key', 'Status', 'Author', 'Created', 'Actions'];
		
		html += '<div style="padding:20px 20px 30px 20px">';
		
		html += '<div class="subtitle">';
			html += 'API Keys';
			html += '<div class="clear"></div>';
		html += '</div>';
		
		var self = this;
		html += this.getBasicTable( this.api_keys, cols, 'key', function(item, idx) {
			var actions = [
				'<span class="link" onMouseUp="$P().edit_api_key('+idx+')"><b>Edit</b></span>',
				'<span class="link" onMouseUp="$P().delete_api_key('+idx+')"><b>Delete</b></span>'
			];
			return [
				'<div class="td_big">' + self.getNiceAPIKey(item, true, col_width) + '</div>',
				'<div style="">' + item.key + '</div>',
				item.active ? '<span class="color_label green"><i class="fa fa-check">&nbsp;</i>Active</span>' : '<span class="color_label red"><i class="fa fa-warning">&nbsp;</i>Suspended</span>',
				self.getNiceUsername(item.username, true, col_width),
				'<span title="'+get_nice_date_time(item.created, true)+'">'+get_nice_date(item.created, true)+'</span>',
				actions.join(' | ')
			];
		} );
		
		html += '<div style="height:30px;"></div>';
		html += '<center><table><tr>';
			html += '<td><div class="button" style="width:130px;" onMouseUp="$P().edit_api_key(-1)"><i class="fa fa-plus-circle">&nbsp;&nbsp;</i>Add API Key...</div></td>';
		html += '</tr></table></center>';
		
		html += '</div>'; // padding
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
	},
	
	edit_api_key: function(idx) {
		// jump to edit sub
		if (idx > -1) Nav.go( '#Admin?sub=edit_api_key&id=' + this.api_keys[idx].id );
		else Nav.go( '#Admin?sub=new_api_key' );
	},
	
	delete_api_key: function(idx) {
		// delete key from search results
		this.api_key = this.api_keys[idx];
		this.show_delete_api_key_dialog();
	},
	
	gosub_new_api_key: function(args) {
		// create new API Key
		var html = '';
		app.setWindowTitle( "New API Key" );
		this.div.removeClass('loading');
		
		html += this.getSidebarTabs( 'new_api_key',
			[
				['activity', "Activity"],
				['alerts', "Alerts"],
				['api_keys', "API Keys"],
				['new_api_key', "New API Key"],
				['commands', "Commands"],
				['groups', "Groups"],
				['monitors', "Monitors"],
				['users', "Users"]
			]
		);
		
		html += '<div style="padding:20px;"><div class="subtitle">New API Key</div></div>';
		
		html += '<div style="padding:0px 20px 50px 20px">';
		html += '<center><table style="margin:0;">';
		
		this.api_key = { privileges: {}, key: get_unique_id() };
		
		html += this.get_api_key_edit_html();
		
		// buttons at bottom
		html += '<tr><td colspan="2" align="center">';
			html += '<div style="height:30px;"></div>';
			
			html += '<table><tr>';
				html += '<td><div class="button" style="width:120px; font-weight:normal;" onMouseUp="$P().cancel_api_key_edit()">Cancel</div></td>';
				html += '<td width="50">&nbsp;</td>';
				
				html += '<td><div class="button" style="width:120px;" onMouseUp="$P().do_new_api_key()"><i class="fa fa-plus-circle">&nbsp;&nbsp;</i>Create Key</div></td>';
			html += '</tr></table>';
			
		html += '</td></tr>';
		
		html += '</table></center>';
		html += '</div>'; // table wrapper div
		
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
		
		setTimeout( function() {
			$('#fe_ak_title').focus();
		}, 1 );
	},
	
	cancel_api_key_edit: function() {
		// cancel editing API Key and return to list
		Nav.go( 'Admin?sub=api_keys' );
	},
	
	do_new_api_key: function(force) {
		// create new API Key
		app.clearError();
		var api_key = this.get_api_key_form_json();
		if (!api_key) return; // error
		
		if (!api_key.title.length) {
			return app.badField('#fe_ak_title', "Please enter an app title for the new API Key.");
		}
		
		this.api_key = api_key;
		
		app.showProgress( 1.0, "Creating API Key..." );
		app.api.post( 'app/create_api_key', api_key, this.new_api_key_finish.bind(this) );
	},
	
	new_api_key_finish: function(resp) {
		// new API Key created successfully
		app.hideProgress();
		
		Nav.go('Admin?sub=edit_api_key&id=' + resp.id);
		
		setTimeout( function() {
			app.showMessage('success', "The new API Key was created successfully.");
		}, 150 );
	},
	
	gosub_edit_api_key: function(args) {
		// edit API Key subpage
		this.div.addClass('loading');
		app.api.post( 'app/get_api_key', { id: args.id }, this.receive_key.bind(this) );
	},
	
	receive_key: function(resp) {
		// edit existing API Key
		var html = '';
		this.api_key = resp.api_key;
		
		app.setWindowTitle( "Editing API Key \"" + (this.api_key.title) + "\"" );
		this.div.removeClass('loading');
		
		html += this.getSidebarTabs( 'edit_api_key',
			[
				['activity', "Activity"],
				['alerts', "Alerts"],
				['api_keys', "API Keys"],
				['edit_api_key', "Edit API Key"],
				['commands', "Commands"],
				['groups', "Groups"],
				['monitors', "Monitors"],
				['users', "Users"]
			]
		);
		
		html += '<div style="padding:20px;"><div class="subtitle">Editing API Key &ldquo;' + (this.api_key.title) + '&rdquo;</div></div>';
		
		html += '<div style="padding:0px 20px 50px 20px">';
		html += '<center>';
		html += '<table style="margin:0;">';
		
		html += this.get_api_key_edit_html();
		
		html += '<tr><td colspan="2" align="center">';
			html += '<div style="height:30px;"></div>';
			
			html += '<table><tr>';
				html += '<td><div class="button" style="width:130px; font-weight:normal;" onMouseUp="$P().cancel_api_key_edit()">Cancel</div></td>';
				html += '<td width="50">&nbsp;</td>';
				html += '<td><div class="button" style="width:130px; font-weight:normal;" onMouseUp="$P().show_delete_api_key_dialog()">Delete Key...</div></td>';
				html += '<td width="50">&nbsp;</td>';
				html += '<td><div class="button" style="width:130px;" onMouseUp="$P().do_save_api_key()"><i class="fa fa-floppy-o">&nbsp;&nbsp;</i>Save Changes</div></td>';
			html += '</tr></table>';
			
		html += '</td></tr>';
		
		html += '</table>';
		html += '</center>';
		html += '</div>'; // table wrapper div
		
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
	},
	
	do_save_api_key: function() {
		// save changes to api key
		app.clearError();
		var api_key = this.get_api_key_form_json();
		if (!api_key) return; // error
		
		this.api_key = api_key;
		
		app.showProgress( 1.0, "Saving API Key..." );
		app.api.post( 'app/update_api_key', api_key, this.save_api_key_finish.bind(this) );
	},
	
	save_api_key_finish: function(resp, tx) {
		// new API Key saved successfully
		app.hideProgress();
		app.showMessage('success', "The API Key was saved successfully.");
		window.scrollTo( 0, 0 );
	},
	
	show_delete_api_key_dialog: function() {
		// show dialog confirming api key delete action
		var self = this;
		app.confirm( '<span style="color:red">Delete API Key</span>', "Are you sure you want to <b>permanently delete</b> the API Key \""+this.api_key.title+"\"?  There is no way to undo this action.", 'Delete', function(result) {
			if (result) {
				app.showProgress( 1.0, "Deleting API Key..." );
				app.api.post( 'app/delete_api_key', self.api_key, self.delete_api_key_finish.bind(self) );
			}
		} );
	},
	
	delete_api_key_finish: function(resp, tx) {
		// finished deleting API Key
		var self = this;
		app.hideProgress();
		
		Nav.go('Admin?sub=api_keys', 'force');
		
		setTimeout( function() {
			app.showMessage('success', "The API Key '"+self.api_key.title+"' was deleted successfully.");
		}, 150 );
	},
	
	get_api_key_edit_html: function() {
		// get html for editing an API Key (or creating a new one)
		var html = '';
		var api_key = this.api_key;
		
		// API Key
		html += get_form_table_row( 'API Key', '<input type="text" id="fe_ak_key" size="40" value="'+escape_text_field_value(api_key.key)+'" spellcheck="false"/>&nbsp;<span class="link addme" onMouseUp="$P().generate_key()" onMouseDown="event.preventDefault();">&laquo; Generate Random</span>' );
		html += get_form_table_caption( "The API Key string is used to authenticate API calls." );
		html += get_form_table_spacer();
		
		// status
		html += get_form_table_row( 'Status', '<select id="fe_ak_status">' + render_menu_options([[1,'Active'], [0,'Disabled']], api_key.active) + '</select>' );
		html += get_form_table_caption( "'Disabled' means that the API Key remains in the system, but it cannot be used for any API calls." );
		html += get_form_table_spacer();
		
		// title
		html += get_form_table_row( 'App Title', '<input type="text" id="fe_ak_title" size="30" value="'+escape_text_field_value(api_key.title)+'" spellcheck="false"/>' );
		html += get_form_table_caption( "Enter the title of the application that will be using the API Key.");
		html += get_form_table_spacer();
		
		// description
		html += get_form_table_row('App Description', '<textarea id="fe_ak_desc" style="width:550px; height:50px; resize:vertical;">'+escape_text_field_value(api_key.description)+'</textarea>');
		html += get_form_table_caption( "Optionally enter a more detailed description of the application." );
		html += get_form_table_spacer();
		
		// privilege list
		var priv_html = '';
		var key_is_admin = !!api_key.privileges.admin;
		
		for (var idx = 0, len = config.privilege_list.length; idx < len; idx++) {
			var priv = config.privilege_list[idx];
			var has_priv = !!api_key.privileges[ priv.id ];
			var priv_visible = (priv.id == 'admin') || !key_is_admin;
			var priv_class = (priv.id == 'admin') ? 'priv_group_admin' : 'priv_group_other';
			
			priv_html += '<div class="'+priv_class+'" style="margin-top:4px; margin-bottom:4px; '+(priv_visible ? '' : 'display:none;')+'">';
			priv_html += '<input type="checkbox" id="fe_ak_priv_'+priv.id+'" value="1" ' + 
				(has_priv ? 'checked="checked" ' : '') + ((priv.id == 'admin') ? 'onChange="$P().change_admin_checkbox()"' : '') + '>';
			priv_html += '<label for="fe_ak_priv_'+priv.id+'">'+priv.title+'</label>';
			priv_html += '</div>';
		}
		
		html += get_form_table_row( 'Privileges', priv_html );
		html += get_form_table_caption( "Select which privileges the API Key account should have. Administrators have all privileges." );
		html += get_form_table_spacer();
		
		return html;
	},
	
	change_admin_checkbox: function() {
		// toggle admin checkbox
		var is_checked = $('#fe_ak_priv_admin').is(':checked');
		if (is_checked) this.div.find('div.priv_group_other').hide(250);
		else this.div.find('div.priv_group_other').show(250);
	},
	
	get_api_key_form_json: function() {
		// get api key elements from form, used for new or edit
		var api_key = this.api_key;
		
		api_key.key = $('#fe_ak_key').val();
		api_key.active = $('#fe_ak_status').val();
		api_key.title = $('#fe_ak_title').val();
		api_key.description = $('#fe_ak_desc').val();
		
		if (!api_key.key.length) {
			return app.badField('#fe_ak_key', "Please enter an API Key string, or generate a random one.");
		}
		
		for (var idx = 0, len = config.privilege_list.length; idx < len; idx++) {
			var priv = config.privilege_list[idx];
			api_key.privileges[ priv.id ] = $('#fe_ak_priv_'+priv.id).is(':checked') ? 1 : 0;
		}
		
		return api_key;
	},
	
	generate_key: function() {
		// generate random api key
		$('#fe_ak_key').val( get_unique_id() );
	}
	
});

// Cronicle Admin Page -- Activity Log

Class.add( Page.Admin, {
	
	activity_types: {
		'^group': '<i class="mdi mdi-server-network">&nbsp;</i>Group',
		'^monitor': '<i class="mdi mdi-chart-line">&nbsp;</i>Monitor',
		'^alert_cleared$': '<i class="mdi mdi-bell-off">&nbsp;</i>Alert',
		'^alert': '<i class="mdi mdi-bell">&nbsp;</i>Alert',
		'^command': '<i class="mdi mdi-console">&nbsp;</i>Command',
		'^apikey': '<i class="mdi mdi-key-variant">&nbsp;</i>API Key',	
		'^user': '<i class="fa fa-user">&nbsp;</i>User',
		'^server': '<i class="mdi mdi-desktop-tower mdi-lg">&nbsp;</i>Server',
		'^state': '<i class="mdi mdi-calendar-clock">&nbsp;</i>State', // mdi-lg
		'^watch': '<i class="mdi mdi-history">&nbsp;</i>Watch', // mdi-lg
		'^error': '<i class="fa fa-exclamation-triangle">&nbsp;</i>Error',
		'^warning': '<i class="fa fa-exclamation-circle">&nbsp;</i>Warning'
	},
	
	gosub_activity: function(args) {
		// show activity log
		app.setWindowTitle( "Activity Log" );
		
		if (!args.offset) args.offset = 0;
		if (!args.limit) args.limit = 25;
		app.api.post( 'app/get_activity', copy_object(args), this.receive_activity.bind(this) );
	},
	
	receive_activity: function(resp) {
		// receive page of activity from server, render it
		this.lastActivityResp = resp;
		
		var html = '';
		this.div.removeClass('loading');
		
		html += this.getSidebarTabs( 'activity',
			[
				['activity', "Activity"],
				['alerts', "Alerts"],
				['api_keys', "API Keys"],
				['commands', "Commands"],
				['groups', "Groups"],
				['monitors', "Monitors"],
				['users', "Users"]
			]
		);
		
		this.events = [];
		if (resp.rows) this.events = resp.rows;
		
		var cols = ['Date/Time', 'Type', 'Description', 'Username', 'IP Address', 'Actions'];
		
		html += '<div style="padding:20px 20px 30px 20px">';
		
		html += '<div class="subtitle">';
			html += 'Activity Log';
			// html += '<div class="clear"></div>';
		html += '</div>';
		
		var self = this;
		html += this.getPaginatedTable( resp, cols, 'item', function(item, idx) {
			// figure out icon first
			if (!item.action) item.action = 'unknown';
			
			var item_type = '';
			for (var key in self.activity_types) {
				var regexp = new RegExp(key);
				if (item.action.match(regexp)) {
					item_type = self.activity_types[key];
					break;
				}
			}
			
			// compose nice description
			var desc = '';
			var actions = [];
			var color = '';
			
			switch (item.action) {
				
				// alerts
				case 'alert_create':
					desc = 'New alert created: <b>' + item.alert.title + '</b>';
					actions.push( '<a href="#Admin?sub=edit_alert&id='+item.alert.id+'">Edit Alert</a>' );
				break;
				case 'alert_update':
					desc = 'Alert updated: <b>' + item.alert.title + '</b>';
					actions.push( '<a href="#Admin?sub=edit_alert&id='+item.alert.id+'">Edit Alert</a>' );
				break;
				case 'alert_delete':
					desc = 'Alert deleted: <b>' + item.alert.title + '</b>';
				break;
				
				case 'alert_new':
					desc = 'Alert Triggered: <b>' + item.def.title + '</b> for server <b>' + self.formatHostname(item.hostname) + '</b>: ' + item.alert.message;
					color = 'red';
					actions.push( '<a href="#Snapshot?id=' + item.hostname + '/' + Math.floor( item.alert.date / 60 ) + '">View Snapshot</a>' );
					
				break;
				
				case 'alert_cleared':
					desc = 'Alert Cleared: <b>' + item.def.title + '</b> for server <b>' + self.formatHostname(item.hostname) + '.';
				break;
				
				// groups
				case 'group_create':
					desc = 'New group created: <b>' + item.group.title + '</b>';
					actions.push( '<a href="#Admin?sub=edit_group&id='+item.group.id+'">Edit Group</a>' );
				break;
				case 'group_update':
					desc = 'Group updated: <b>' + item.group.title + '</b>';
					actions.push( '<a href="#Admin?sub=edit_group&id='+item.group.id+'">Edit Group</a>' );
				break;
				case 'group_multi_update':
					desc = 'Group sort order changed.</b>';
				break;
				case 'group_delete':
					desc = 'Group deleted: <b>' + item.group.title + '</b>';
				break;
				
				// monitors
				case 'monitor_create':
					desc = 'New monitor created: <b>' + item.monitor.title + '</b>';
					actions.push( '<a href="#Admin?sub=edit_monitor&id='+item.monitor.id+'">Edit Monitor</a>' );
				break;
				case 'monitor_update':
					desc = 'Monitor updated: <b>' + item.monitor.title + '</b>';
					actions.push( '<a href="#Admin?sub=edit_monitor&id='+item.monitor.id+'">Edit Monitor</a>' );
				break;
				case 'monitor_multi_update':
					desc = 'Monitor sort order changed.</b>';
				break;
				case 'monitor_delete':
					desc = 'Monitor deleted: <b>' + item.monitor.title + '</b>';
				break;
				
				// commands
				case 'command_create':
					desc = 'New command created: <b>' + item.command.title + '</b>';
					actions.push( '<a href="#Admin?sub=edit_command&id='+item.command.id+'">Edit Command</a>' );
				break;
				case 'command_update':
					desc = 'Command updated: <b>' + item.command.title + '</b>';
					actions.push( '<a href="#Admin?sub=edit_command&id='+item.command.id+'">Edit Command</a>' );
				break;
				case 'command_delete':
					desc = 'Command deleted: <b>' + item.command.title + '</b>';
				break;
				
				// api keys
				case 'apikey_create':
					desc = 'New API Key created: <b>' + item.api_key.title + '</b> (Key: ' + item.api_key.key + ')';
					actions.push( '<a href="#Admin?sub=edit_api_key&id='+item.api_key.id+'">Edit Key</a>' );
				break;
				case 'apikey_update':
					desc = 'API Key updated: <b>' + item.api_key.title + '</b> (Key: ' + item.api_key.key + ')';
					actions.push( '<a href="#Admin?sub=edit_api_key&id='+item.api_key.id+'">Edit Key</a>' );
				break;
				case 'apikey_delete':
					desc = 'API Key deleted: <b>' + item.api_key.title + '</b> (Key: ' + item.api_key.key + ')';
				break;
				
				// users
				case 'user_create':
					desc = 'New user account created: <b>' + item.user.username + "</b> (" + item.user.full_name + ")";
					actions.push( '<a href="#Admin?sub=edit_user&username='+item.user.username+'">Edit User</a>' );
				break;
				case 'user_update':
					desc = 'User account updated: <b>' + item.user.username + "</b> (" + item.user.full_name + ")";
					actions.push( '<a href="#Admin?sub=edit_user&username='+item.user.username+'">Edit User</a>' );
				break;
				case 'user_delete':
					desc = 'User account deleted: <b>' + item.user.username + "</b> (" + item.user.full_name + ")";
				break;
				case 'user_login':
					desc = "User logged in: <b>" + item.user.username + "</b> (" + item.user.full_name + ")";
				break;
				
				// servers
				case 'server_add':
					desc = 'New server added to ' + item.group.title + ': <b>' + app.formatHostname(item.hostname) + '</b> (' + item.ip + ')';
				break;
				
				// state
				case 'state_update':
					if (item.alert_snooze) desc = "Alerts have been snoozed until <b>" + get_nice_date_time(item.alert_snooze, false, false) + "</b>";
					else if (item.alert_snooze === 0) desc = "Alerts have been reactivated.";
					else desc = "State data was updated.";
				break;
				
				// watch
				case 'watch_set':
					if (item.hostname) item.hostnames = [item.hostname];
					var nice_host = app.formatHostname(item.hostnames[0]);
					if (item.hostnames.length > 1) {
						var remain = item.hostnames.length - 1;
						nice_host += " and " + remain + " " + pluralize("other", remain);
					}
					if (item.date) desc = "Server watch set on " + nice_host + " until: <b>" + get_nice_date_time(item.date, false, false) + "</b>";
					else desc = "Server watch canceled for: " + nice_host;
				break;
				
				// errors
				case 'error':
					desc = encode_entities( item.description );
					color = 'red';
				break;
				
				// warnings
				case 'warning':
					desc = encode_entities( item.description );
					color = 'yellow';
				break;
				
			} // action
			
			var tds = [
				'<div style="white-space:nowrap;">' + get_nice_date_time( item.epoch || 0, false, true ) + '</div>',
				'<div class="td_big" style="white-space:nowrap; font-size:12px; font-weight:normal;">' + item_type + '</div>',
				'<div class="activity_desc">' + desc + '</div>',
				'<div style="white-space:nowrap;">' + self.getNiceUsername(item, true) + '</div>',
				(item.ip || 'n/a').replace(/^\:\:ffff\:(\d+\.\d+\.\d+\.\d+)$/, '$1'),
				'<div style="white-space:nowrap;">' + actions.join(' | ') + '</div>'
			];
			if (color) tds.className = color;
			
			return tds;
		} );
		
		html += '</div>'; // padding
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
	}
	
});
// Admin Page -- Alert Config

Class.add( Page.Admin, {
	
	gosub_alerts: function(args) {
		// show alert list
		app.setWindowTitle( "Alerts" );
		this.div.addClass('loading');
		app.api.post( 'app/get_alerts', copy_object(args), this.receive_alerts.bind(this) );
	},
	
	receive_alerts: function(resp) {
		// receive all alerts from server, render them sorted
		var html = '';
		this.div.removeClass('loading');
		
		var size = get_inner_window_size();
		var col_width = Math.floor( ((size.width * 0.9) + 200) / 6 );
		
		if (!resp.rows) resp.rows = [];
		
		// update local cache, just in case
		config.alerts = resp.rows;
		
		// sort by title ascending
		this.alerts = resp.rows.sort( function(a, b) {
			return a.title.toLowerCase().localeCompare( b.title.toLowerCase() );
		} );
		
		html += this.getSidebarTabs( 'alerts',
			[
				['activity', "Activity"],
				['alerts', "Alerts"],
				['api_keys', "API Keys"],
				['commands', "Commands"],
				['groups', "Groups"],
				['monitors', "Monitors"],
				['users', "Users"]
			]
		);
		
		var cols = ['<i class="fa fa-check-square-o"></i>', 'Alert Title', 'Alert ID', 'Groups', 'Author', 'Created', 'Actions'];
		
		html += '<div style="padding:20px 20px 30px 20px">';
		
		html += '<div class="subtitle">';
			html += 'Alerts';
			html += '<div class="clear"></div>';
		html += '</div>';
		
		var self = this;
		html += this.getBasicTable( this.alerts, cols, 'alert', function(item, idx) {
			var actions = [
				'<span class="link" onMouseUp="$P().edit_alert('+idx+')"><b>Edit</b></span>',
				'<span class="link" onMouseUp="$P().delete_alert('+idx+')"><b>Delete</b></span>'
			];
			var tds = [
				'<input type="checkbox" style="cursor:pointer" onChange="$P().change_alert_enabled('+idx+')" '+(item.enabled ? 'checked="checked"' : '')+'/>', 
				'<div class="td_big">' + self.getNiceAlert(item, true, col_width) + '</div>',
				'<code>' + item.id + '</code>',
				self.getNiceGroupList(item.group_match, true, col_width),
				self.getNiceUsername(item.username, true, col_width),
				'<span title="'+get_nice_date_time(item.created, true)+'">'+get_nice_date(item.created, true)+'</span>',
				actions.join(' | ')
			];
			
			if (!item.enabled) {
				if (tds.className) tds.className += ' '; else tds.className = '';
				tds.className += 'disabled';
			}
			
			return tds;
		} );
		
		html += '<div style="height:30px;"></div>';
		html += '<center><table><tr>';
			html += '<td><div class="button" style="width:130px;" onMouseUp="$P().edit_alert(-1)"><i class="fa fa-plus-circle">&nbsp;&nbsp;</i>Add Alert...</div></td>';
		html += '</tr></table></center>';
		
		html += '</div>'; // padding
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
	},
	
	change_alert_enabled: function(idx) {
		// toggle alert on / off
		var self = this;
		var alert = this.alerts[idx];
		alert.enabled = alert.enabled ? false : true;
		
		var stub = {
			id: alert.id,
			enabled: alert.enabled,
		};
		
		app.api.post( 'app/update_alert', stub, function(resp) {
			self.receive_alerts({ rows: self.alerts });
		} );
	},
	
	edit_alert: function(idx) {
		// jump to edit sub
		if (idx > -1) Nav.go( '#Admin?sub=edit_alert&id=' + this.alerts[idx].id );
		else Nav.go( '#Admin?sub=new_alert' );
	},
	
	delete_alert: function(idx) {
		// delete alert from search results
		this.alert = this.alerts[idx];
		this.show_delete_alert_dialog();
	},
	
	gosub_new_alert: function(args) {
		// create new alert
		var html = '';
		app.setWindowTitle( "New Alert" );
		this.div.removeClass('loading');
		
		html += this.getSidebarTabs( 'new_alert',
			[
				['activity', "Activity"],
				['alerts', "Alerts"],
				['new_alert', "New Alert"],
				['api_keys', "API Keys"],
				['commands', "Commands"],
				['groups', "Groups"],
				['monitors', "Monitors"],
				['users', "Users"]
			]
		);
		
		html += '<div style="padding:20px;"><div class="subtitle">New Alert</div></div>';
		
		html += '<div style="padding:0px 20px 50px 20px">';
		html += '<center><table style="margin:0;">';
		
		this.alert = {
			"id": "",
			"title": "",
			"expression": "",
			"message": "",
			"group_match": ".+",
			"email": "",
			"web_hook": "",
			"enabled": true
		};
		
		html += this.get_alert_edit_html();
		
		// buttons at bottom
		html += '<tr><td colspan="2" align="center">';
			html += '<div style="height:30px;"></div>';
			
			html += '<table><tr>';
				html += '<td><div class="button" style="width:120px; font-weight:normal;" onMouseUp="$P().cancel_alert_edit()">Cancel</div></td>';
				html += '<td width="50">&nbsp;</td>';
				
				html += '<td><div class="button" style="width:120px;" onMouseUp="$P().do_new_alert()"><i class="fa fa-plus-circle">&nbsp;&nbsp;</i>Add Alert</div></td>';
			html += '</tr></table>';
			
		html += '</td></tr>';
		
		html += '</table></center>';
		html += '</div>'; // table wrapper div
		
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
		
		setTimeout( function() {
			$('#fe_ea_id').focus();
		}, 1 );
	},
	
	cancel_alert_edit: function() {
		// cancel editing alert and return to list
		Nav.go( 'Admin?sub=alerts' );
	},
	
	do_new_alert: function(force) {
		// create new alert
		app.clearError();
		var alert = this.get_alert_form_json();
		if (!alert) return; // error
		
		this.alert = alert;
		
		app.showProgress( 1.0, "Creating Alert..." );
		app.api.post( 'app/create_alert', alert, this.new_alert_finish.bind(this) );
	},
	
	new_alert_finish: function(resp) {
		// new alert created successfully
		app.hideProgress();
		
		// update client cache
		config.alerts.push( copy_object(this.alert) );
		
		// Nav.go('Admin?sub=edit_alert&id=' + this.alert.id);
		Nav.go('Admin?sub=alerts');
		
		setTimeout( function() {
			app.showMessage('success', "The new alert was created successfully.");
		}, 150 );
	},
	
	gosub_edit_alert: function(args) {
		// edit alert subpage
		this.div.addClass('loading');
		app.api.post( 'app/get_alert', { id: args.id }, this.receive_alert.bind(this) );
	},
	
	receive_alert: function(resp) {
		// edit existing alert
		var html = '';
		this.alert = resp.alert;
		
		app.setWindowTitle( "Editing Alert \"" + (this.alert.title) + "\"" );
		this.div.removeClass('loading');
		
		html += this.getSidebarTabs( 'edit_alert',
			[
				['activity', "Activity"],
				['alerts', "Alerts"],
				['edit_alert', "Edit Alert"],
				['api_keys', "API Keys"],
				['commands', "Commands"],
				['groups', "Groups"],
				['monitors', "Monitors"],
				['users', "Users"]
			]
		);
		
		html += '<div style="padding:20px;"><div class="subtitle">Editing Alert &ldquo;' + (this.alert.title) + '&rdquo;</div></div>';
		
		html += '<div style="padding:0px 20px 50px 20px">';
		html += '<center>';
		html += '<table style="margin:0;">';
		
		html += this.get_alert_edit_html();
		
		html += '<tr><td colspan="2" align="center">';
			html += '<div style="height:30px;"></div>';
			
			html += '<table><tr>';
				html += '<td><div class="button" style="width:130px; font-weight:normal;" onMouseUp="$P().cancel_alert_edit()">Cancel</div></td>';
				html += '<td width="50">&nbsp;</td>';
				html += '<td><div class="button" style="width:130px; font-weight:normal;" onMouseUp="$P().show_delete_alert_dialog()">Delete Alert...</div></td>';
				html += '<td width="50">&nbsp;</td>';
				html += '<td><div class="button" style="width:130px;" onMouseUp="$P().do_save_alert()"><i class="fa fa-floppy-o">&nbsp;&nbsp;</i>Save Changes</div></td>';
			html += '</tr></table>';
			
		html += '</td></tr>';
		
		html += '</table>';
		html += '</center>';
		html += '</div>'; // table wrapper div
		
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
	},
	
	do_save_alert: function() {
		// save changes to alert
		app.clearError();
		var alert = this.get_alert_form_json();
		if (!alert) return; // error
		
		this.alert = alert;
		
		app.showProgress( 1.0, "Saving Alert..." );
		app.api.post( 'app/update_alert', alert, this.save_alert_finish.bind(this) );
	},
	
	save_alert_finish: function(resp, tx) {
		// new alert saved successfully
		app.hideProgress();
		app.showMessage('success', "The alert was saved successfully.");
		window.scrollTo( 0, 0 );
		
		// update client cache
		var alert_idx = find_object_idx( config.alerts, { id: this.alert.id } );
		if (alert_idx > -1) {
			config.alerts[alert_idx] = copy_object(this.alert);
		}
		else {
			config.alerts.push( copy_object(this.alert) );
		}
	},
	
	show_delete_alert_dialog: function() {
		// show dialog confirming alert delete action
		var self = this;
		app.confirm( '<span style="color:red">Delete Alert</span>', "Are you sure you want to <b>permanently delete</b> the alert \""+this.alert.title+"\"?  There is no way to undo this action.", 'Delete', function(result) {
			if (result) {
				app.showProgress( 1.0, "Deleting Alert..." );
				app.api.post( 'app/delete_alert', self.alert, self.delete_alert_finish.bind(self) );
			}
		} );
	},
	
	delete_alert_finish: function(resp, tx) {
		// finished deleting alert
		var self = this;
		app.hideProgress();
		
		// update client cache
		var alert_idx = find_object_idx( config.alerts, { id: this.alert.id } );
		if (alert_idx > -1) {
			config.alerts.splice( alert_idx, 1 );
		}
		
		Nav.go('Admin?sub=alerts', 'force');
		
		setTimeout( function() {
			app.showMessage('success', "The alert '"+self.alert.title+"' was deleted successfully.");
		}, 150 );
	},
	
	get_alert_edit_html: function() {
		// get html for editing an alert (or creating a new one)
		var html = '';
		var alert = this.alert;
		
		// id
		html += get_form_table_row( 'Alert ID', '<input type="text" id="fe_ea_id" size="20" value="'+escape_text_field_value(alert.id)+'" spellcheck="false" ' + (alert.id ? 'disabled="disabled"' : '') + '/>' );
		html += get_form_table_caption( "Enter a unique ID for the alert (alphanumerics only).  Once created this cannot be changed.");
		html += get_form_table_spacer();
		
		// title
		html += get_form_table_row( 'Alert Title', '<input type="text" id="fe_ea_title" size="30" value="'+escape_text_field_value(alert.title)+'" spellcheck="false"/>' );
		html += get_form_table_caption( "Enter the title of the alert, for display purposes.");
		html += get_form_table_spacer();
		
		// enabled
		html += get_form_table_row( 'Notify', '<input type="checkbox" id="fe_ea_enabled" value="1" ' + (alert.enabled ? 'checked="checked"' : '') + '/><label for="fe_ea_enabled">Notifications Enabled</label>' );
		html += get_form_table_caption( "Check this box to enable e-mail and web hook notifications for the alert." );
		html += get_form_table_spacer();
		
		// group match
		html += get_form_table_row( 'Groups', this.renderGroupSelector('fe_ea', alert.group_match) );
		html += get_form_table_caption( "Select which groups the alert should apply to.");
		html += get_form_table_spacer();
		
		// "expression": "[load_avg] >= ([cpus/length] + 1)",
		html += get_form_table_row( 'Expression', '<textarea id="fe_ea_expression" style="width:550px; height:50px; resize:vertical;">'+escape_text_field_value(alert.expression)+'</textarea>' );
		html += get_form_table_spacer();
		
		// "message": "CPU load average is too high: [load_avg] ([cpus/length] CPU cores)",
		html += get_form_table_row( 'Message', '<textarea id="fe_ea_message" style="width:550px; height:50px; resize:vertical;">'+escape_text_field_value(alert.message)+'</textarea>' );
		html += get_form_table_spacer();
		
		// optionally attach to monitor for label overlays?
		var monitor_items = [ ['', "(None)"] ].concat(
			config.monitors.sort( function(a, b) {
				return (a.sort_order < b.sort_order) ? -1 : 1;
			} )
		);
		html += get_form_table_row( 'Overlay', '<select id="fe_ea_monitor">' + render_menu_options(monitor_items, alert.monitor_id) + '</select>' );
		html += get_form_table_caption( "Optionally select a monitor to overlay alert annotations on." );
		html += get_form_table_spacer();
		
		// "email": "",
		html += get_form_table_row( 'Email', '<input type="text" id="fe_ea_email" size="50" value="'+escape_text_field_value(alert.email)+'" spellcheck="false" placeholder="email@sample.com" spellcheck="false" onChange="$P().update_add_remove_me($(this))"/><span class="link addme" onMouseUp="$P().add_remove_me($(this).prev())"></span>' );
		html += get_form_table_caption( "Optionally customize the e-mail recipients to be notified for this alert.");
		html += get_form_table_spacer();
		
		// "web_hook": "",
		html += get_form_table_row( 'Web Hook', '<input type="text" id="fe_ea_web_hook" size="50" value="'+escape_text_field_value(alert.web_hook)+'" spellcheck="false" placeholder="https://"/>' );
		html += get_form_table_caption( "Optionally enter a custom Web Hook URL for this alert.");
		html += get_form_table_spacer();
		
		// notes
		html += get_form_table_row( 'Notes', '<textarea id="fe_ea_notes" style="width:550px; height:50px; resize:vertical;">'+escape_text_field_value(alert.notes)+'</textarea>' );
		html += get_form_table_caption( "Optionally enter notes for the alert, which will be included in all e-mail notifications." );
		html += get_form_table_spacer();
		
		setTimeout( function() {
			$P().update_add_remove_me( $('#fe_ea_email') );
		}, 1 );
		
		return html;
	},
	
	get_alert_form_json: function() {
		// get api key elements from form, used for new or edit
		var alert = this.alert;
		
		alert.id = $('#fe_ea_id').val().replace(/\W+/g, '').toLowerCase();
		alert.title = $('#fe_ea_title').val();
		alert.enabled = $('#fe_ea_enabled').is(':checked') ? true : false;
		alert.group_match = this.getGroupSelectorValue('fe_ea');
		alert.expression = $('#fe_ea_expression').val();
		alert.message = $('#fe_ea_message').val();
		alert.email = $('#fe_ea_email').val();
		alert.web_hook = $('#fe_ea_web_hook').val();
		alert.notes = $('#fe_ea_notes').val();
		alert.monitor_id = $('#fe_ea_monitor').val();
		
		if (!alert.id.length) {
			return app.badField('#fe_ea_id', "Please enter a unique alphanumeric ID for the alert.");
		}
		if (!alert.title.length) {
			return app.badField('#fe_ea_title', "Please enter a title for the alert.");
		}
		
		return alert;
	}
	
});

// Admin Page -- Command Config

Class.add( Page.Admin, {
	
	gosub_commands: function(args) {
		// show command list
		app.setWindowTitle( "Commands" );
		this.div.addClass('loading');
		app.api.post( 'app/get_commands', copy_object(args), this.receive_commands.bind(this) );
	},
	
	receive_commands: function(resp) {
		// receive all commands from server, render them sorted
		var html = '';
		this.div.removeClass('loading');
		
		var size = get_inner_window_size();
		var col_width = Math.floor( ((size.width * 0.9) + 200) / 6 );
		
		if (!resp.rows) resp.rows = [];
		
		// update local cache, just in case
		config.commands = resp.rows;
		
		// sort by title ascending
		this.commands = resp.rows.sort( function(a, b) {
			return a.title.toLowerCase().localeCompare( b.title.toLowerCase() );
		} );
		
		html += this.getSidebarTabs( 'commands',
			[
				['activity', "Activity"],
				['alerts', "Alerts"],
				['api_keys', "API Keys"],
				['commands', "Commands"],
				['groups', "Groups"],
				['monitors', "Monitors"],
				['users', "Users"]
			]
		);
		
		var cols = ['<i class="fa fa-check-square-o"></i>', 'Command Title', 'Command ID', 'Groups', 'Author', 'Created', 'Actions'];
		
		html += '<div style="padding:20px 20px 30px 20px">';
		
		html += '<div class="subtitle">';
			html += 'Commands';
			html += '<div class="clear"></div>';
		html += '</div>';
		
		var self = this;
		html += this.getBasicTable( this.commands, cols, 'command', function(item, idx) {
			var actions = [
				'<span class="link" onMouseUp="$P().edit_command('+idx+')"><b>Edit</b></span>',
				'<span class="link" onMouseUp="$P().delete_command('+idx+')"><b>Delete</b></span>'
			];
			var tds = [
				'<input type="checkbox" style="cursor:pointer" onChange="$P().change_command_enabled('+idx+')" '+(item.enabled ? 'checked="checked"' : '')+'/>', 
				'<div class="td_big">' + self.getNiceCommand(item, true, col_width) + '</div>',
				'<code>' + item.id + '</code>',
				self.getNiceGroupList(item.group_match, true, col_width),
				self.getNiceUsername(item.username, true, col_width),
				'<span title="'+get_nice_date_time(item.created, true)+'">'+get_nice_date(item.created, true)+'</span>',
				actions.join(' | ')
			];
			
			tds.className = 'checkbox_first_col';
			
			if (!item.enabled) {
				if (tds.className) tds.className += ' '; else tds.className = '';
				tds.className += 'disabled';
			}
			
			return tds;
		} );
		
		html += '<div style="height:30px;"></div>';
		html += '<center><table><tr>';
			html += '<td><div class="button" style="width:130px;" onMouseUp="$P().edit_command(-1)"><i class="fa fa-plus-circle">&nbsp;&nbsp;</i>Add Command...</div></td>';
		html += '</tr></table></center>';
		
		html += '</div>'; // padding
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
	},
	
	change_command_enabled: function(idx) {
		// toggle command on / off
		var self = this;
		var command = this.commands[idx];
		command.enabled = command.enabled ? false : true;
		
		var stub = {
			id: command.id,
			enabled: command.enabled,
		};
		
		app.api.post( 'app/update_command', stub, function(resp) {
			self.receive_commands({ rows: self.commands });
		} );
	},
	
	edit_command: function(idx) {
		// jump to edit sub
		if (idx > -1) Nav.go( '#Admin?sub=edit_command&id=' + this.commands[idx].id );
		else Nav.go( '#Admin?sub=new_command' );
	},
	
	delete_command: function(idx) {
		// delete command from search results
		this.command = this.commands[idx];
		this.show_delete_command_dialog();
	},
	
	gosub_new_command: function(args) {
		// create new command
		var html = '';
		app.setWindowTitle( "New Command" );
		this.div.removeClass('loading');
		
		html += this.getSidebarTabs( 'new_command',
			[
				['activity', "Activity"],
				['alerts', "Alerts"],
				['api_keys', "API Keys"],
				['commands', "Commands"],
				['new_command', "New Command"],
				['groups', "Groups"],
				['monitors', "Monitors"],
				['users', "Users"]
			]
		);
		
		html += '<div style="padding:20px;"><div class="subtitle">New Command</div></div>';
		
		html += '<div style="padding:0px 20px 50px 20px">';
		html += '<center><table style="margin:0;">';
		
		this.command = {
			"id": "",
			"title": "",
			"exec": "/bin/sh",
			"script": "",
			"group_match": ".+",
			"enabled": true,
			"format": "text",
			"timeout": 5
		};
		
		html += this.get_command_edit_html();
		
		// buttons at bottom
		html += '<tr><td colspan="2" align="center">';
			html += '<div style="height:30px;"></div>';
			
			html += '<table><tr>';
				html += '<td><div class="button" style="width:120px; font-weight:normal;" onMouseUp="$P().cancel_command_edit()">Cancel</div></td>';
				html += '<td width="50">&nbsp;</td>';
				
				html += '<td><div class="button" style="width:120px;" onMouseUp="$P().do_new_command()"><i class="fa fa-plus-circle">&nbsp;&nbsp;</i>Add Command</div></td>';
			html += '</tr></table>';
			
		html += '</td></tr>';
		
		html += '</table></center>';
		html += '</div>'; // table wrapper div
		
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
		
		setTimeout( function() {
			$('#fe_ec_id').focus();
		}, 1 );
	},
	
	cancel_command_edit: function() {
		// cancel editing command and return to list
		Nav.go( 'Admin?sub=commands' );
	},
	
	do_new_command: function(force) {
		// create new command
		app.clearError();
		var command = this.get_command_form_json();
		if (!command) return; // error
		
		this.command = command;
		
		app.showProgress( 1.0, "Creating Command..." );
		app.api.post( 'app/create_command', command, this.new_command_finish.bind(this) );
	},
	
	new_command_finish: function(resp) {
		// new command created successfully
		app.hideProgress();
		
		// update client cache
		config.commands.push( copy_object(this.command) );
		
		// Nav.go('Admin?sub=edit_command&id=' + this.command.id);
		Nav.go('Admin?sub=commands');
		
		setTimeout( function() {
			app.showMessage('success', "The new command was created successfully.");
		}, 150 );
	},
	
	gosub_edit_command: function(args) {
		// edit command subpage
		this.div.addClass('loading');
		app.api.post( 'app/get_command', { id: args.id }, this.receive_command.bind(this) );
	},
	
	receive_command: function(resp) {
		// edit existing command
		var html = '';
		this.command = resp.command;
		
		app.setWindowTitle( "Editing Command \"" + (this.command.title) + "\"" );
		this.div.removeClass('loading');
		
		html += this.getSidebarTabs( 'edit_command',
			[
				['activity', "Activity"],
				['alerts', "Alerts"],
				['api_keys', "API Keys"],
				['commands', "Commands"],
				['edit_command', "Edit Command"],
				['groups', "Groups"],
				['monitors', "Monitors"],
				['users', "Users"]
			]
		);
		
		html += '<div style="padding:20px;"><div class="subtitle">Editing Command &ldquo;' + (this.command.title) + '&rdquo;</div></div>';
		
		html += '<div style="padding:0px 20px 50px 20px">';
		html += '<center>';
		html += '<table style="margin:0;">';
		
		html += this.get_command_edit_html();
		
		html += '<tr><td colspan="2" align="center">';
			html += '<div style="height:30px;"></div>';
			
			html += '<table><tr>';
				html += '<td><div class="button" style="width:130px; font-weight:normal;" onMouseUp="$P().cancel_command_edit()">Cancel</div></td>';
				html += '<td width="50">&nbsp;</td>';
				html += '<td><div class="button" style="width:130px; font-weight:normal;" onMouseUp="$P().show_delete_command_dialog()">Delete Command...</div></td>';
				html += '<td width="50">&nbsp;</td>';
				html += '<td><div class="button" style="width:130px;" onMouseUp="$P().do_save_command()"><i class="fa fa-floppy-o">&nbsp;&nbsp;</i>Save Changes</div></td>';
			html += '</tr></table>';
			
		html += '</td></tr>';
		
		html += '</table>';
		html += '</center>';
		html += '</div>'; // table wrapper div
		
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
	},
	
	do_save_command: function() {
		// save changes to command
		app.clearError();
		var command = this.get_command_form_json();
		if (!command) return; // error
		
		this.command = command;
		
		app.showProgress( 1.0, "Saving Command..." );
		app.api.post( 'app/update_command', command, this.save_command_finish.bind(this) );
	},
	
	save_command_finish: function(resp, tx) {
		// new command saved successfully
		app.hideProgress();
		app.showMessage('success', "The command was saved successfully.");
		window.scrollTo( 0, 0 );
		
		// update client cache
		var command_idx = find_object_idx( config.commands, { id: this.command.id } );
		if (command_idx > -1) {
			config.commands[command_idx] = copy_object(this.command);
		}
		else {
			config.commands.push( copy_object(this.command) );
		}
	},
	
	show_delete_command_dialog: function() {
		// show dialog confirming command delete action
		var self = this;
		app.confirm( '<span style="color:red">Delete Command</span>', "Are you sure you want to <b>permanently delete</b> the command \""+this.command.title+"\"?  There is no way to undo this action.", 'Delete', function(result) {
			if (result) {
				app.showProgress( 1.0, "Deleting Command..." );
				app.api.post( 'app/delete_command', self.command, self.delete_command_finish.bind(self) );
			}
		} );
	},
	
	delete_command_finish: function(resp, tx) {
		// finished deleting command
		var self = this;
		app.hideProgress();
		
		// update client cache
		var command_idx = find_object_idx( config.commands, { id: this.command.id } );
		if (command_idx > -1) {
			config.commands.splice( command_idx, 1 );
		}
		
		Nav.go('Admin?sub=commands', 'force');
		
		setTimeout( function() {
			app.showMessage('success', "The command '"+self.command.title+"' was deleted successfully.");
		}, 150 );
	},
	
	get_command_edit_html: function() {
		// get html for editing an command (or creating a new one)
		var html = '';
		var command = this.command;
		
		// id
		html += get_form_table_row( 'Command ID', '<input type="text" id="fe_ec_id" size="20" value="'+escape_text_field_value(command.id)+'" spellcheck="false" ' + (command.id ? 'disabled="disabled"' : '') + '/>' );
		html += get_form_table_caption( "Enter a unique ID for the command (alphanumerics only).  Once created this cannot be changed.");
		html += get_form_table_spacer();
		
		// title
		html += get_form_table_row( 'Command Title', '<input type="text" id="fe_ec_title" size="30" value="'+escape_text_field_value(command.title)+'" spellcheck="false"/>' );
		html += get_form_table_caption( "Enter the title of the command, for display purposes.");
		html += get_form_table_spacer();
		
		// enabled
		html += get_form_table_row( 'Active', '<input type="checkbox" id="fe_ec_enabled" value="1" ' + (command.enabled ? 'checked="checked"' : '') + '/><label for="fe_ec_enabled">Command Enabled</label>' );
		html += get_form_table_caption( "Only enabled commands will be executed on matching servers." );
		html += get_form_table_spacer();
		
		// group match
		html += get_form_table_row( 'Groups', this.renderGroupSelector('fe_ec', command.group_match) );
		html += get_form_table_caption( "Select which groups the command should apply to.");
		html += get_form_table_spacer();
		
		// exec
		html += get_form_table_row( 'Shell', '<input type="text" id="fe_ec_exec" size="40" class="mono" value="'+escape_text_field_value(command.exec)+'" spellcheck="false"/>' );
		html += get_form_table_caption( "Enter the shell interpreter path to process your command script.<br/>This can also be a non-shell interpreter such as <b>/usr/bin/perl</b> or <b>/usr/bin/python</b>.");
		html += get_form_table_spacer();
		
		// script
		html += get_form_table_row( 'Script', '<textarea id="fe_ec_script" style="width:600px; height:80px; resize:vertical;">'+escape_text_field_value(command.script)+'</textarea>' );
		html += get_form_table_caption( "Enter the script source to be executed using the selected interpreter." );
		html += get_form_table_spacer();
		
		// format
		html += get_form_table_row( 'Format', '<select id="fe_ec_format">' + render_menu_options([['text', "Text"], ['json', "JSON"], ['xml', "XML"]], command.format) + '</select>' );
		html += get_form_table_caption( "Select the output format that the script generates, so it can be parsed correctly." );
		html += get_form_table_spacer();
		
		// timeout
		html += get_form_table_row( 'Timeout', '<input type="text" id="fe_ec_timeout" size="5" value="'+escape_text_field_value(command.timeout)+'" spellcheck="false"/><span style="font-size:11px">&nbsp;(seconds)</span>' );
		html += get_form_table_caption( "Enter the maximum time to allow the command to run, in seconds.");
		html += get_form_table_spacer();
		
		// uid
		html += get_form_table_row( 'User ID', '<input type="text" id="fe_ec_uid" size="20" value="'+escape_text_field_value(command.uid)+'" spellcheck="false"/>' );
		html += get_form_table_caption( "Optionally enter a custom User ID to run the command as.<br/>The UID may be either numerical or a username string ('root', 'wheel', etc.).");
		html += get_form_table_spacer();
		
		// notes
		html += get_form_table_row( 'Notes', '<textarea id="fe_ec_notes" style="width:500px; height:50px; resize:vertical;">'+escape_text_field_value(command.notes)+'</textarea>' );
		html += get_form_table_caption( "Optionally enter any notes for the command, for your own use." );
		html += get_form_table_spacer();
		
		return html;
	},
	
	get_command_form_json: function() {
		// get api key elements from form, used for new or edit
		var command = this.command;
		
		command.id = $('#fe_ec_id').val().replace(/\W+/g, '').toLowerCase();
		command.title = $('#fe_ec_title').val();
		command.enabled = $('#fe_ec_enabled').is(':checked') ? true : false;
		command.group_match = this.getGroupSelectorValue('fe_ec');
		command.exec = $('#fe_ec_exec').val();
		command.script = $('#fe_ec_script').val();
		command.format = $('#fe_ec_format').val();
		command.timeout = parseInt( $('#fe_ec_timeout').val() ) || 0;
		command.uid = $('#fe_ec_uid').val();
		command.notes = $('#fe_ec_notes').val();
		
		if (!command.id.length) {
			return app.badField('#fe_ec_id', "Please enter a unique alphanumeric ID for the command.");
		}
		if (!command.title.length) {
			return app.badField('#fe_ec_title', "Please enter a title for the command.");
		}
		if (!command.exec.length) {
			return app.badField('#fe_ec_exec', "Please enter a shell interpreter path.");
		}
		if (!command.script.length) {
			return app.badField('#fe_ec_script', "Please enter the script source to be executed.");
		}
		if (!command.timeout || (command.timeout < 0)) {
			return app.badField('#fe_ec_timeout', "Please enter a number of seconds for the command timeout.");
		}
		
		return command;
	}
	
});

// Admin Page -- Group Config

Class.add( Page.Admin, {
	
	gosub_groups: function(args) {
		// show group list
		app.setWindowTitle( "Groups" );
		this.div.addClass('loading');
		app.api.post( 'app/get_groups', copy_object(args), this.receive_groups.bind(this) );
	},
	
	receive_groups: function(resp) {
		// receive all groups from server, render them sorted
		var html = '';
		this.div.removeClass('loading');
		
		var size = get_inner_window_size();
		var col_width = Math.floor( ((size.width * 0.9) + 200) / 6 );
		
		if (!resp.rows) resp.rows = [];
		
		// update local cache, just in case
		config.groups = resp.rows;
		
		// sort by custom sort order
		this.groups = resp.rows.sort( function(a, b) {
			return (a.sort_order < b.sort_order) ? -1 : 1;
		} );
		
		html += this.getSidebarTabs( 'groups',
			[
				['activity', "Activity"],
				['alerts', "Alerts"],
				['api_keys', "API Keys"],
				['commands', "Commands"],
				['groups', "Groups"],
				['monitors', "Monitors"],
				['users', "Users"]
			]
		);
		
		var cols = ['<i class="mdi mdi-menu"></i>', 'Group Title', 'Group ID', 'Hostname Pattern', 'Author', 'Created', 'Actions'];
		
		html += '<div style="padding:20px 20px 30px 20px">';
		
		html += '<div class="subtitle">';
			html += 'Groups';
			html += '<div class="clear"></div>';
		html += '</div>';
		
		var self = this;
		html += this.getBasicTable( this.groups, cols, 'group', function(item, idx) {
			var actions = [];
			// if (idx > 0) actions.push('<span class="link" onMouseUp="$P().group_move_up('+idx+')" title="Move Up"><i class="fa fa-arrow-up"></i></span>');
			// if (idx < self.groups.length - 1) actions.push('<span class="link" onMouseUp="$P().group_move_down('+idx+')" title="Move Down"><i class="fa fa-arrow-down"></i></span>');
			actions.push( '<span class="link" onMouseUp="$P().edit_group('+idx+')"><b>Edit</b></span>' );
			actions.push( '<span class="link" onMouseUp="$P().delete_group('+idx+')"><b>Delete</b></span>' );
			
			var nice_match = '';
			if (item.hostname_match == '(?!)') nice_match = '(None)';
			else nice_match = '<span style="font-family:monospace">/' + item.hostname_match + '/</span>';
			
			return [
				'<div class="td_drag_handle" draggable="true" title="Drag to reorder"><i class="mdi mdi-menu"></i></div>',
				'<div class="td_big">' + self.getNiceGroup(item, true, col_width) + '</div>',
				'<div style="">' + item.id + '</div>',
				'<div class="ellip" style="max-width:'+col_width+'px;">' + nice_match + '</div>',
				self.getNiceUsername(item.username, true, col_width),
				'<span title="'+get_nice_date_time(item.created, true)+'">'+get_nice_date(item.created, true)+'</span>',
				actions.join(' | ')
			];
		} );
		
		html += '<div style="height:30px;"></div>';
		html += '<center><table><tr>';
			html += '<td><div class="button" style="width:130px;" onMouseUp="$P().edit_group(-1)"><i class="fa fa-plus-circle">&nbsp;&nbsp;</i>Add Group...</div></td>';
		html += '</tr></table></center>';
		
		html += '</div>'; // padding
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
		
		this.setupDraggableTable({
			table_sel: this.div.find('table.data_table'), 
			handle_sel: 'td div.td_drag_handle', 
			drag_ghost_sel: 'td div.td_big', 
			drag_ghost_x: 5, 
			drag_ghost_y: 10, 
			callback: this.group_move.bind(this)
		});
	},
	
	group_move: function($rows) {
		// a drag operation has been completed
		var items = [];
		
		$rows.each( function(idx) {
			var $row = $(this);
			items.push({
				id: $row.data('id'),
				sort_order: idx
			});
		});
		
		var data = {
			items: items
		};
		app.api.post( 'app/multi_update_group', data, function(resp) {
			// done
		} );
	},
	
	edit_group: function(idx) {
		// jump to edit sub
		if (idx > -1) Nav.go( '#Admin?sub=edit_group&id=' + this.groups[idx].id );
		else Nav.go( '#Admin?sub=new_group' );
	},
	
	delete_group: function(idx) {
		// delete group from search results
		this.group = this.groups[idx];
		this.show_delete_group_dialog();
	},
	
	gosub_new_group: function(args) {
		// create new group
		var html = '';
		app.setWindowTitle( "New Group" );
		this.div.removeClass('loading');
		
		html += this.getSidebarTabs( 'new_group',
			[
				['activity', "Activity"],
				['alerts', "Alerts"],
				['api_keys', "API Keys"],
				['commands', "Commands"],
				['groups', "Groups"],
				['new_group', "New Group"],
				['monitors', "Monitors"],
				['users', "Users"]
			]
		);
		
		html += '<div style="padding:20px;"><div class="subtitle">New Group</div></div>';
		
		html += '<div style="padding:0px 20px 50px 20px">';
		html += '<center><table style="margin:0;">';
		
		this.group = {
			id: "",
			title: "",
			hostname_match: "",
			alerts_enabled: true
		};
		
		html += this.get_group_edit_html();
		
		// buttons at bottom
		html += '<tr><td colspan="2" align="center">';
			html += '<div style="height:30px;"></div>';
			
			html += '<table><tr>';
				html += '<td><div class="button" style="width:120px; font-weight:normal;" onMouseUp="$P().cancel_group_edit()">Cancel</div></td>';
				html += '<td width="50">&nbsp;</td>';
				
				html += '<td><div class="button" style="width:120px;" onMouseUp="$P().do_new_group()"><i class="fa fa-plus-circle">&nbsp;&nbsp;</i>Add Group</div></td>';
			html += '</tr></table>';
			
		html += '</td></tr>';
		
		html += '</table></center>';
		html += '</div>'; // table wrapper div
		
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
		
		setTimeout( function() {
			$('#fe_eg_id').focus();
		}, 1 );
	},
	
	cancel_group_edit: function() {
		// cancel editing group and return to list
		Nav.go( 'Admin?sub=groups' );
	},
	
	do_new_group: function(force) {
		// create new group
		app.clearError();
		var group = this.get_group_form_json();
		if (!group) return; // error
		
		this.group = group;
		
		app.showProgress( 1.0, "Creating Group..." );
		app.api.post( 'app/create_group', group, this.new_group_finish.bind(this) );
	},
	
	new_group_finish: function(resp) {
		// new group created successfully
		app.hideProgress();
		
		// update client cache
		config.groups.push( copy_object(this.group) );
		
		// update menus
		app.initJumpMenus();
		app.initControlMenus();
		
		// Nav.go('Admin?sub=edit_group&id=' + this.group.id);
		Nav.go('Admin?sub=groups');
		
		setTimeout( function() {
			app.showMessage('success', "The new group was created successfully.");
		}, 150 );
	},
	
	gosub_edit_group: function(args) {
		// edit group subpage
		this.div.addClass('loading');
		app.api.post( 'app/get_group', { id: args.id }, this.receive_group.bind(this) );
	},
	
	receive_group: function(resp) {
		// edit existing group
		var html = '';
		this.group = resp.group;
		
		app.setWindowTitle( "Editing Group \"" + (this.group.title) + "\"" );
		this.div.removeClass('loading');
		
		html += this.getSidebarTabs( 'edit_group',
			[
				['activity', "Activity"],
				['alerts', "Alerts"],
				['api_keys', "API Keys"],
				['commands', "Commands"],
				['groups', "Groups"],
				['edit_group', "Edit Group"],
				['monitors', "Monitors"],
				['users', "Users"]
			]
		);
		
		html += '<div style="padding:20px;"><div class="subtitle">Editing Group &ldquo;' + (this.group.title) + '&rdquo;</div></div>';
		
		html += '<div style="padding:0px 20px 50px 20px">';
		html += '<center>';
		html += '<table style="margin:0;">';
		
		html += this.get_group_edit_html();
		
		html += '<tr><td colspan="2" align="center">';
			html += '<div style="height:30px;"></div>';
			
			html += '<table><tr>';
				html += '<td><div class="button" style="width:130px; font-weight:normal;" onMouseUp="$P().cancel_group_edit()">Cancel</div></td>';
				html += '<td width="50">&nbsp;</td>';
				html += '<td><div class="button" style="width:130px; font-weight:normal;" onMouseUp="$P().show_delete_group_dialog()">Delete Group...</div></td>';
				html += '<td width="50">&nbsp;</td>';
				html += '<td><div class="button" style="width:130px;" onMouseUp="$P().do_save_group()"><i class="fa fa-floppy-o">&nbsp;&nbsp;</i>Save Changes</div></td>';
			html += '</tr></table>';
			
		html += '</td></tr>';
		
		html += '</table>';
		html += '</center>';
		html += '</div>'; // table wrapper div
		
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
	},
	
	do_save_group: function() {
		// save changes to group
		app.clearError();
		var group = this.get_group_form_json();
		if (!group) return; // error
		
		this.group = group;
		
		app.showProgress( 1.0, "Saving Group..." );
		app.api.post( 'app/update_group', group, this.save_group_finish.bind(this) );
	},
	
	save_group_finish: function(resp, tx) {
		// new group saved successfully
		app.hideProgress();
		app.showMessage('success', "The group was saved successfully.");
		window.scrollTo( 0, 0 );
		
		// update client cache
		var group_idx = find_object_idx( config.groups, { id: this.group.id } );
		if (group_idx > -1) {
			config.groups[group_idx] = copy_object(this.group);
		}
		else {
			config.groups.push( copy_object(this.group) );
		}
		
		// update menus
		app.initJumpMenus();
		app.initControlMenus();
	},
	
	show_delete_group_dialog: function() {
		// show dialog confirming group delete action
		var self = this;
		if (config.groups.length < 2) return app.doError("Sorry, you cannot delete the last group.");
		
		app.confirm( '<span style="color:red">Delete Group</span>', "Are you sure you want to <b>permanently delete</b> the group \""+this.group.title+"\"?  There is no way to undo this action.", 'Delete', function(result) {
			if (result) {
				app.showProgress( 1.0, "Deleting Group..." );
				app.api.post( 'app/delete_group', self.group, self.delete_group_finish.bind(self) );
			}
		} );
	},
	
	delete_group_finish: function(resp, tx) {
		// finished deleting group
		var self = this;
		app.hideProgress();
		
		// update client cache
		var group_idx = find_object_idx( config.groups, { id: this.group.id } );
		if (group_idx > -1) {
			config.groups.splice( group_idx, 1 );
		}
		
		// update menus
		app.initJumpMenus();
		app.initControlMenus();
		
		Nav.go('Admin?sub=groups', 'force');
		
		setTimeout( function() {
			app.showMessage('success', "The group '"+self.group.title+"' was deleted successfully.");
		}, 150 );
	},
	
	get_group_edit_html: function() {
		// get html for editing an group (or creating a new one)
		var html = '';
		var group = this.group;
		
		// id
		html += get_form_table_row( 'Group ID', '<input type="text" id="fe_eg_id" size="20" value="'+escape_text_field_value(group.id)+'" spellcheck="false" ' + (group.id ? 'disabled="disabled"' : '') + '/>' );
		html += get_form_table_caption( "Enter a unique ID for the group (alphanumerics only).  Once created this cannot be changed.");
		html += get_form_table_spacer();
		
		// title
		html += get_form_table_row( 'Group Title', '<input type="text" id="fe_eg_title" size="30" value="'+escape_text_field_value(group.title)+'" spellcheck="false"/>' );
		html += get_form_table_caption( "Enter the title of the group, for display purposes.");
		html += get_form_table_spacer();
		
		// hostname_match
		html += get_form_table_row( 'Hostname Match', '<input type="text" id="fe_eg_match" size="40" class="mono" value="'+escape_text_field_value((group.hostname_match == '(?!)') ? "" : group.hostname_match)+'" spellcheck="false"/>' );
		html += get_form_table_caption( "Optionally enter a regular expression match to auto-include hostnames in the group.<br/>To match <b>all servers</b>, set this to <code>.+</code>");
		html += get_form_table_spacer();
		
		// alert notifications enabled
		html += get_form_table_row( 'Alerts', '<input type="checkbox" id="fe_eg_alerts" value="1" ' + (group.alerts_enabled ? 'checked="checked"' : '') + '/><label for="fe_eg_alerts">Alert Notifications Enabled</label>' );
		html += get_form_table_caption( "You can enable or disable alert notifications for the entire group here." );
		html += get_form_table_spacer();
		
		// default email
		html += get_form_table_row( 'Alert Email', '<input type="text" id="fe_eg_alert_email" size="50" value="'+escape_text_field_value(group.alert_email)+'" spellcheck="false" placeholder="email@sample.com" spellcheck="false" onChange="$P().update_add_remove_me($(this))"/><span class="link addme" onMouseUp="$P().add_remove_me($(this).prev())"></span>' );
		html += get_form_table_caption( "Optionally set the default e-mail recipients to be notified for alerts in this group.<br/>Note that individual alerts can override this setting.");
		html += get_form_table_spacer();
		
		// default web hook
		html += get_form_table_row( 'Alert Web Hook', '<input type="text" id="fe_eg_alert_web_hook" size="50" value="'+escape_text_field_value(group.alert_web_hook)+'" spellcheck="false" placeholder="https://"/>' );
		html += get_form_table_caption( "Optionally set the default web hook URL for alerts in this group.<br/>Note that individual alerts can override this setting.");
		html += get_form_table_spacer();
		
		// notes
		html += get_form_table_row( 'Notes', '<textarea id="fe_eg_notes" style="width:500px; height:50px; resize:vertical;">'+escape_text_field_value(group.notes)+'</textarea>' );
		html += get_form_table_caption( "Optionally enter any notes for the group, for your own use." );
		html += get_form_table_spacer();
		
		return html;
	},
	
	get_group_form_json: function() {
		// get api key elements from form, used for new or edit
		var group = this.group;
		
		group.id = $('#fe_eg_id').val().replace(/\W+/g, '').toLowerCase();
		group.title = $('#fe_eg_title').val();
		group.hostname_match = $('#fe_eg_match').val();
		group.alerts_enabled = $('#fe_eg_alerts').is(':checked') ? true : false;
		group.alert_email = $('#fe_eg_alert_email').val();
		group.alert_web_hook = $('#fe_eg_alert_web_hook').val();
		group.notes = $('#fe_eg_notes').val();
		
		if (!group.id.length) {
			return app.badField('#fe_eg_id', "Please enter a unique alphanumeric ID for the group.");
		}
		if (!group.title.length) {
			return app.badField('#fe_eg_title', "Please enter a title for the group.");
		}
		if (!group.hostname_match) {
			// default to never-match regexp
			group.hostname_match = '(?!)';
		}
		
		// test regexp, as it was entered by a user
		try { new RegExp(group.hostname_match); }
		catch(err) {
			return app.badField('fe_eg_match', "Invalid regular expression: " + err);
		}
		
		return group;
	}
	
});

// Admin Page -- Monitor Config

Class.add( Page.Admin, {
	
	gosub_monitors: function(args) {
		// show monitor list
		app.setWindowTitle( "Monitors" );
		this.div.addClass('loading');
		app.api.post( 'app/get_monitors', copy_object(args), this.receive_monitors.bind(this) );
	},
	
	receive_monitors: function(resp) {
		// receive all monitors from server, render them sorted
		var self = this;
		var html = '';
		this.div.removeClass('loading');
		
		var size = get_inner_window_size();
		var col_width = Math.floor( ((size.width * 0.9) + 200) / 6 );
		
		if (!resp.rows) resp.rows = [];
		
		// update local cache, just in case
		config.monitors = resp.rows;
		
		// sort by custom sort order
		this.monitors = resp.rows.sort( function(a, b) {
			return (a.sort_order < b.sort_order) ? -1 : 1;
		} );
		
		html += this.getSidebarTabs( 'monitors',
			[
				['activity', "Activity"],
				['alerts', "Alerts"],
				['api_keys', "API Keys"],
				['commands', "Commands"],
				['groups', "Groups"],
				['monitors', "Monitors"],
				['users', "Users"]
			]
		);
		
		var cols = ['<i class="mdi mdi-menu"></i>', 'Monitor Title', 'Monitor ID', 'Groups', 'Author', 'Created', 'Actions'];
		
		html += '<div style="padding:20px 20px 30px 20px">';
		
		html += '<div class="subtitle">';
			html += 'Monitors';
			html += '<div class="clear"></div>';
		html += '</div>';
		
		var self = this;
		html += this.getBasicTable( this.monitors, cols, 'monitor', function(item, idx) {
			var actions = [];
			// if (idx > 0) actions.push('<span class="link" onMouseUp="$P().move_up('+idx+')" title="Move Up"><i class="fa fa-arrow-up"></i></span>');
			// if (idx < self.monitors.length - 1) actions.push('<span class="link" onMouseUp="$P().move_down('+idx+')" title="Move Down"><i class="fa fa-arrow-down"></i></span>');
			actions.push('<span class="link" onMouseUp="$P().edit_monitor('+idx+')"><b>Edit</b></span>');
			actions.push('<span class="link" onMouseUp="$P().delete_monitor('+idx+')"><b>Delete</b></span>');
			
			var tds = [
				'<div class="td_drag_handle" draggable="true" title="Drag to reorder"><i class="mdi mdi-menu"></i></div>',
				// '<input type="checkbox" style="cursor:pointer" onChange="$P().change_monitor_display('+idx+')" '+(item.display ? 'checked="checked"' : '')+'/>', 
				'<div class="td_big">' + self.getNiceMonitor(item, true, col_width) + '</div>',
				'<code>' + item.id + '</code>',
				self.getNiceGroupList(item.group_match, true, col_width),
				self.getNiceUsername(item.username, true, col_width),
				'<span title="'+get_nice_date_time(item.created, true)+'">'+get_nice_date(item.created, true)+'</span>',
				actions.join(' | ')
			];
			
			tds.className = 'checkbox_first_col';
			
			if (!item.display) {
				if (tds.className) tds.className += ' '; else tds.className = '';
				tds.className += 'disabled';
			}
			
			return tds;
		} );
		
		html += '<div style="height:30px;"></div>';
		html += '<center><table><tr>';
			html += '<td><div class="button" style="width:130px;" onMouseUp="$P().edit_monitor(-1)"><i class="fa fa-plus-circle">&nbsp;&nbsp;</i>Add Monitor...</div></td>';
		html += '</tr></table></center>';
		
		html += '</div>'; // padding
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
		
		this.setupDraggableTable({
			table_sel: this.div.find('table.data_table'), 
			handle_sel: 'td div.td_drag_handle', 
			drag_ghost_sel: 'td div.td_big', 
			drag_ghost_x: 5, 
			drag_ghost_y: 10, 
			callback: this.monitor_move.bind(this)
		});
	},
	
	change_monitor_display: function(idx) {
		// toggle monitor display on / off
		var self = this;
		var monitor = this.monitors[idx];
		monitor.display = monitor.display ? false : true;
		
		var stub = {
			id: monitor.id,
			display: monitor.display,
		};
		
		app.api.post( 'app/update_monitor', stub, function(resp) {
			self.receive_monitors({ rows: self.monitors });
		} );
	},
	
	monitor_move: function($rows) {
		// a drag operation has been completed
		var items = [];
		
		$rows.each( function(idx) {
			var $row = $(this);
			items.push({
				id: $row.data('id'),
				sort_order: idx
			});
		});
		
		var data = {
			items: items
		};
		app.api.post( 'app/multi_update_monitor', data, function(resp) {
			// done
		} );
	},
	
	edit_monitor: function(idx) {
		// jump to edit sub
		if (idx > -1) Nav.go( '#Admin?sub=edit_monitor&id=' + this.monitors[idx].id );
		else Nav.go( '#Admin?sub=new_monitor' );
	},
	
	delete_monitor: function(idx) {
		// delete monitor from search results
		this.monitor = this.monitors[idx];
		this.show_delete_monitor_dialog();
	},
	
	gosub_new_monitor: function(args) {
		// create new monitor
		var html = '';
		app.setWindowTitle( "New Monitor" );
		this.div.removeClass('loading');
		
		html += this.getSidebarTabs( 'new_monitor',
			[
				['activity', "Activity"],
				['alerts', "Alerts"],
				['api_keys', "API Keys"],
				['commands', "Commands"],
				['groups', "Groups"],
				['monitors', "Monitors"],
				['new_monitor', "New Monitor"],
				['users', "Users"]
			]
		);
		
		html += '<div style="padding:20px;"><div class="subtitle">New Monitor</div></div>';
		
		html += '<div style="padding:0px 20px 50px 20px">';
		html += '<center><table style="margin:0;">';
		
		this.monitor = {
			"id": "",
			"title": "",
			"source": "",
			"data_type": "float",
			"suffix": "",
			"merge_type": "",
			"group_match": ".+",
			"display": true
		};
		
		html += this.get_monitor_edit_html();
		
		// buttons at bottom
		html += '<tr><td colspan="2" align="center">';
			html += '<div style="height:30px;"></div>';
			
			html += '<table><tr>';
				html += '<td><div class="button" style="width:120px; font-weight:normal;" onMouseUp="$P().cancel_monitor_edit()">Cancel</div></td>';
				html += '<td width="50">&nbsp;</td>';
				
				html += '<td><div class="button" style="width:120px;" onMouseUp="$P().do_new_monitor()"><i class="fa fa-plus-circle">&nbsp;&nbsp;</i>Add Monitor</div></td>';
			html += '</tr></table>';
			
		html += '</td></tr>';
		
		html += '</table></center>';
		html += '</div>'; // table wrapper div
		
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
		
		setTimeout( function() {
			$('#fe_em_id').focus();
		}, 1 );
	},
	
	cancel_monitor_edit: function() {
		// cancel editing monitor and return to list
		Nav.go( 'Admin?sub=monitors' );
	},
	
	do_new_monitor: function(force) {
		// create new monitor
		app.clearError();
		var monitor = this.get_monitor_form_json();
		if (!monitor) return; // error
		
		this.monitor = monitor;
		
		app.showProgress( 1.0, "Creating Monitor..." );
		app.api.post( 'app/create_monitor', monitor, this.new_monitor_finish.bind(this) );
	},
	
	new_monitor_finish: function(resp) {
		// new monitor created successfully
		app.hideProgress();
		
		// update client cache
		config.monitors.push( copy_object(this.monitor) );
		
		// Nav.go('Admin?sub=edit_monitor&id=' + this.monitor.id);
		Nav.go('Admin?sub=monitors');
		
		setTimeout( function() {
			app.showMessage('success', "The new monitor was created successfully.");
		}, 150 );
	},
	
	gosub_edit_monitor: function(args) {
		// edit monitor subpage
		this.div.addClass('loading');
		app.api.post( 'app/get_monitor', { id: args.id }, this.receive_monitor.bind(this) );
	},
	
	receive_monitor: function(resp) {
		// edit existing monitor
		var html = '';
		this.monitor = resp.monitor;
		
		app.setWindowTitle( "Editing Monitor \"" + (this.monitor.title) + "\"" );
		this.div.removeClass('loading');
		
		html += this.getSidebarTabs( 'edit_monitor',
			[
				['activity', "Activity"],
				['alerts', "Alerts"],
				['api_keys', "API Keys"],
				['commands', "Commands"],
				['groups', "Groups"],
				['monitors', "Monitors"],
				['edit_monitor', "Edit Monitor"],
				['users', "Users"]
			]
		);
		
		html += '<div style="padding:20px;"><div class="subtitle">Editing Monitor &ldquo;' + (this.monitor.title) + '&rdquo;</div></div>';
		
		html += '<div style="padding:0px 20px 50px 20px">';
		html += '<center>';
		html += '<table style="margin:0;">';
		
		html += this.get_monitor_edit_html();
		
		html += '<tr><td colspan="2" align="center">';
			html += '<div style="height:30px;"></div>';
			
			html += '<table><tr>';
				html += '<td><div class="button" style="width:130px; font-weight:normal;" onMouseUp="$P().cancel_monitor_edit()">Cancel</div></td>';
				html += '<td width="50">&nbsp;</td>';
				html += '<td><div class="button" style="width:130px; font-weight:normal;" onMouseUp="$P().show_delete_monitor_dialog()">Delete Monitor...</div></td>';
				html += '<td width="50">&nbsp;</td>';
				html += '<td><div class="button" style="width:130px;" onMouseUp="$P().do_save_monitor()"><i class="fa fa-floppy-o">&nbsp;&nbsp;</i>Save Changes</div></td>';
			html += '</tr></table>';
			
		html += '</td></tr>';
		
		html += '</table>';
		html += '</center>';
		html += '</div>'; // table wrapper div
		
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
	},
	
	do_save_monitor: function() {
		// save changes to monitor
		app.clearError();
		var monitor = this.get_monitor_form_json();
		if (!monitor) return; // error
		
		this.monitor = monitor;
		
		app.showProgress( 1.0, "Saving Monitor..." );
		app.api.post( 'app/update_monitor', monitor, this.save_monitor_finish.bind(this) );
	},
	
	save_monitor_finish: function(resp, tx) {
		// new monitor saved successfully
		app.hideProgress();
		app.showMessage('success', "The monitor was saved successfully.");
		window.scrollTo( 0, 0 );
		
		// update client cache
		var mon_idx = find_object_idx( config.monitors, { id: this.monitor.id } );
		if (mon_idx > -1) {
			config.monitors[mon_idx] = copy_object(this.monitor);
		}
		else {
			config.monitors.push( copy_object(this.monitor) );
		}
	},
	
	show_delete_monitor_dialog: function() {
		// show dialog confirming monitor delete action
		var self = this;
		if (config.monitors.length < 2) return app.doError("Sorry, you cannot delete the last monitor.");
		
		app.confirm( '<span style="color:red">Delete Monitor</span>', "Are you sure you want to <b>permanently delete</b> the monitor \""+this.monitor.title+"\"?  There is no way to undo this action.", 'Delete', function(result) {
			if (result) {
				app.showProgress( 1.0, "Deleting Monitor..." );
				app.api.post( 'app/delete_monitor', self.monitor, self.delete_monitor_finish.bind(self) );
			}
		} );
	},
	
	delete_monitor_finish: function(resp, tx) {
		// finished deleting monitor
		var self = this;
		app.hideProgress();
		
		// update client cache
		var mon_idx = find_object_idx( config.monitors, { id: this.monitor.id } );
		if (mon_idx > -1) {
			config.monitors.splice( mon_idx, 1 );
		}
		
		Nav.go('Admin?sub=monitors', 'force');
		
		setTimeout( function() {
			app.showMessage('success', "The monitor '"+self.monitor.title+"' was deleted successfully.");
		}, 150 );
	},
	
	get_monitor_edit_html: function() {
		// get html for editing an monitor (or creating a new one)
		var html = '';
		var monitor = this.monitor;
		
		// id
		html += get_form_table_row( 'Monitor ID', '<input type="text" id="fe_em_id" size="20" value="'+escape_text_field_value(monitor.id)+'" spellcheck="false" ' + (monitor.id ? 'disabled="disabled"' : '') + '/>' );
		html += get_form_table_caption( "Enter a unique ID for the monitor (alphanumerics only).  Once created this cannot be changed.");
		html += get_form_table_spacer();
		
		// title
		html += get_form_table_row( 'Monitor Title', '<input type="text" id="fe_em_title" size="30" value="'+escape_text_field_value(monitor.title)+'" spellcheck="false"/>' );
		html += get_form_table_caption( "Enter a title of the monitor, for display purposes.");
		html += get_form_table_spacer();
		
		// display enabled
		html += get_form_table_row( 'Display', '<input type="checkbox" id="fe_em_display" value="1" ' + (monitor.display ? 'checked="checked"' : '') + '/><label for="fe_em_display">Show Monitor Graphs</label>' );
		html += get_form_table_caption( "Select whether this monitor should display a visible graph or not." );
		html += get_form_table_spacer();
		
		// group match
		html += get_form_table_row( 'Groups', this.renderGroupSelector('fe_em', monitor.group_match) );
		html += get_form_table_caption( "Select which groups the monitor should apply to.");
		html += get_form_table_spacer();
		
		// data source
		html += get_form_table_row( 'Data Source', '<input type="text" id="fe_em_source" size="40" class="mono" value="'+escape_text_field_value(monitor.source)+'" spellcheck="false"/><span class="link addme" onMouseUp="$P().showHostDataExplorer($(this).prev())"><i class="fa fa-search">&nbsp;</i>Explore...</span>' );

		html += get_form_table_spacer();
		
		// data regexp
		html += get_form_table_row( 'Data Match', '<input type="text" id="fe_em_data_match" size="40" class="mono" value="'+escape_text_field_value(monitor.data_match)+'" spellcheck="false"/>' );
		html += get_form_table_caption( "Optionally enter a regular expression to grab the desired data value out of a string.<br/>Surround the match with parenthesis to isolate it.  This is mainly for custom commands.");
		html += get_form_table_spacer();
		
		// data type (integer, float, bytes, seconds, percent)
		var type_items = [
			['integer', "Integer"],
			['float', "Float"],
			['bytes', "Bytes"],
			['seconds', "Seconds"],
			['milliseconds', "Milliseconds"]
			// ['percent', "Percent"]
		];
		html += get_form_table_row( 'Data Type', '<select id="fe_em_data_type">' + render_menu_options(type_items, monitor.data_type) + '</select>' );
		html += get_form_table_caption( "Select the data type for the monitor, which controls how the value is read and displayed." );
		html += get_form_table_spacer();
		
		// delta
		html += get_form_table_row( 'Delta', 
			'<div style=""><input type="checkbox" id="fe_em_delta" value="1" ' + (monitor.delta ? 'checked="checked"' : '') + ' onChange="$P().changeDeltaCheckbox(this)"/><label for="fe_em_delta">Calculate as Delta</label></div>' + 
			'<div style="margin-top:3px;"><input type="checkbox" id="fe_em_divide_by_delta" value="1" ' + (monitor.delta ? '' : 'disabled="disabled"') + ' ' + (monitor.divide_by_delta ? 'checked="checked"' : '') + '/><label for="fe_em_divide_by_delta">Divide by Time</label></div>' 
		);
		html += get_form_table_caption( "Optionally interpret the data value as a delta, and optionally divided by time.<br/>This is mainly for values that constantly count up, but we want to graph the difference over time." );
		html += get_form_table_spacer();
		
		// suffix
		html += get_form_table_row( 'Data Suffix', '<input type="text" id="fe_em_suffix" size="20" value="'+escape_text_field_value(monitor.suffix)+'" spellcheck="false"/>' );
		html += get_form_table_caption( "Optionally enter a suffix to be displayed after the data value, e.g. <code>/sec</code>.");
		html += get_form_table_spacer();
		
		// overview (merge_type)
		html += get_form_table_row( 'Overview', '<select id="fe_em_merge_type">' + render_menu_options([['', "None"], ['avg', "Average"], ['total', "Total"]], monitor.merge_type) + '</select>' );
		html += get_form_table_caption( "Select the method by which multi-server data should be merged together for the overview page.<br/>Select 'None' to hide this monitor on the overview page entirely." );
		html += get_form_table_spacer();
		
		// notes
		html += get_form_table_row( 'Notes', '<textarea id="fe_em_notes" style="width:500px; height:50px; resize:vertical;">'+escape_text_field_value(monitor.notes)+'</textarea>' );
		html += get_form_table_caption( "Optionally enter any notes for the monitor, for your own use." );
		html += get_form_table_spacer();
		
		return html;
	},
	
	changeDeltaCheckbox: function(elem) {
		// change delta checkbox, toggle disabled state of divide-by-delta
		if ($(elem).is(':checked')) $('#fe_em_divide_by_delta').removeAttr('disabled');
		else $('#fe_em_divide_by_delta').attr('disabled', true);
	},
	
	get_monitor_form_json: function() {
		// get api key elements from form, used for new or edit
		var monitor = this.monitor;
		
		monitor.id = $('#fe_em_id').val().replace(/\W+/g, '').toLowerCase();
		monitor.title = $('#fe_em_title').val();
		monitor.group_match = this.getGroupSelectorValue('fe_em');
		monitor.source = $('#fe_em_source').val();
		monitor.data_match = $('#fe_em_data_match').val();
		monitor.data_type = $('#fe_em_data_type').val();
		monitor.suffix = $('#fe_em_suffix').val();
		monitor.merge_type = $('#fe_em_merge_type').val();
		monitor.notes = $('#fe_em_notes').val();
		monitor.display = $('#fe_em_display').is(':checked') ? true : false;
		
		if (!monitor.id.length) {
			return app.badField('#fe_em_id', "Please enter a unique alphanumeric ID for the monitor.");
		}
		if (!monitor.title.length) {
			return app.badField('#fe_em_title', "Please enter a display title for the monitor.");
		}
		if (monitor.data_match) {
			// test regexp, as it was entered by a user
			try { new RegExp(monitor.data_match); }
			catch(err) {
				return app.badField('fe_em_data_match', "Invalid regular expression: " + err);
			}
		}
		
		return monitor;
	}
	
});

