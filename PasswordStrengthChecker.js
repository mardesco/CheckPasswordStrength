/*
PasswordStrengthChecker.js 
version 0.2.3
https://github.com/mardesco/CheckPasswordStrength
(c)2014 by Jesse Smith  [http://www.jesse-smith.net]
Dual licensed under the MIT and GPL licenses.

Credits: Special thanks to Daniel Convissor.  
This script incorporates concepts and regular expressions 
based on his WordPress plugin
"Login Security Solution."
*/
;
var PWChecker = PWChecker || function(){




	// vars
	var pw='',
	strength=0,
	passed = false,
	minLength = 8,
	suggestedLength = 14,
	complexLength = 30,
	regExp,
	errors=[];
	
	
	// extend the String object with a replacement for PHP's str_replace function
	// thanks to http://stackoverflow.com/questions/5069464/replace-multiple-strings-at-once/5069776#5069776
	String.prototype.str_replace = function(find, replace) {
	  var replaceString = this;
	  for (var i = 0; i < find.length; i++) {
		replaceString = replaceString.replace(find[i], replace[i]);
	  }
	  return replaceString;
	};	
	
	
	//check the strength of a password
	this.check = function(input){
	
		
		// reset the strength
		strength = 0;
		
		// and the errors array
		errors = [];
		
		// optimistic initial condition
		passed = true;
		
		// convert the input to a string if it's not already
		pw = input.toString();
		

		// does the password contain non-ASCII characters?
		if( is_pw_outside_ascii() ){
		
			errors.push('The password must be within the standard range of ASCII characters.');
			passed = false;
			strength -= 1;
			}else{
			
			strength += 1;
			
			}
		
		
		// does the password meet the minimum length requirement?
		if(pw.length < minLength){
			errors.push("The password must be at least " + minLength + " characters long.");
			passed = false;
			strength -= 1;
		}else{
			strength += 1;
		}
		
		
		// is the password so long that we don't have to test it for additional complexity?
		if(pw.length >= complexLength){
			strength += 10;
		}else{
			// password does not meet length required to avoid complexity check
			// don't fail them or subtract points from strength
			// just subject the password to rigorous testing.
			
		
			// does the password contain both upper and lower case letters?
			if( pw_uses_only_one_character_case() ){
				errors.push("The password must contain both upper and lower case letters.");
				passed = false;
				strength -= 1;
			}else{
				strength += 1;
			}
			
			
			
			// does the password contain at least one number?
			if( pw_lacks_digits() ){
				errors.push('Password must contain at least one number.');
				passed = false;
				strength -= 1;
			}else{
				strength += 1;
			}
			
			// does the password contain at least one symbolic/punctuation character?
			
			if( pw_lacks_special_chars() ){
				errors.push('Password must contain at least one punctuation character, like *!@#$%^&*()_+-=[]?<>{},.;');
				passed = false;
				strength -= 1;
			}else{
				strength += 1;
			}
			
			// does the password contain sequential characters?
			if( does_pw_contain_sequential_chars() ){
				errors.push("Passwords may not contain a sequential series of characters. The password you entered would be too easily guessed by an attacker.");
				passed = false;
				strength -= 1;
			}else{
				strength += 1;
			}
			
			
			
			
			// is the password based on a common dictionary word, or a slight variation thereof?
			if( is_common_dictionary_word() ){
				errors.push('Passwords must not contain common dictionary words.  The password you entered would be too easily guessed by an attacker.');
				passed = false;
				strength -= 1;
			}else{
				strength += 1;
			}			
			

		}// end complexity check.
		
	}
	
	// is the password similar to the user's e-mail address?	
	this.isPasswordSimilarToEmail = function(input){
		if(typeof(input) != 'string'){
			errors.push("Invalid argument: e-mail address.");
			passed = false;
			strength -= 1;
		}
		if( input.indexOf('@') == -1 || input.indexOf('.') == -1){
			errors.push("Invalid argument: e-mail address.");
			passed = false;
			strength -= 1;
		}		
		var parts = input.split('@');
		var little_bits = new Array();
		// for email addresses like first.last@company.com
		var first_parts = parts[0].split('.');
		for(var i=0; i<first_parts.length; i++){
			little_bits.push(first_parts[i].toLowerCase());
		}
		
		//now for the main part of the domain
		var domain_parts = parts[1].split('.');
		little_bits.push(domain_parts[0].toLowerCase());
		
		
		if(test_against_banned_word_list(little_bits)){
			errors.push("Entered password is too similar to supplied email address.");
			passed = false;
			strength -= 1;
			return true;
		}else{
			strength += 1;
			return false;
		}		
		
	}
	

	this.getMinLength = function(){return minLength;}
	
	this.isPasswordOk = function(){return passed;}
	
	this.getErrors = function(){
		return errors;
		}
	
	// does password contain characters outside the standard ASCII set?
	function is_pw_outside_ascii() {
		// we only want ASCII characters from 32 to 126
		// this regex tests "is the string between the ! and the ~, or is it a space?"
		regExp = new RegExp(/^[!-~ ]+$/);
		// had to remove the terminal 'u' (which tested "is UTF-8") - it breaks the JavaScript.
		
		// return the opposite, because if it does NOT match, then it IS a bad one.
		return !regExp.test(pw);
	}
	
	function pw_uses_only_one_character_case(){
	
		// first lets see if it has any letters at all
		regExp = new RegExp(/^[\P{L}\p{Nd}]+$/);
		if(regExp.test(pw)){
			return true;
		}
	
		//var upper = pw.toUpperCase();//upper == pw ||
		var lower = pw.toLowerCase();
		
		// had to re-think the logic here...
		if( lower == pw){
		
			return true;
		}else{
		

			return false;
		}
		
	}
	

	function pw_lacks_digits(){
		// matches a string that contains at least one digit
		regExp = new RegExp(/\d/);
		// return the opposite.
		return !regExp.test(pw);
	}
	
	
	function pw_lacks_special_chars(){
		
		regExp = new RegExp(/(_|\W)/);
	
		return !regExp.test(pw);
	}
	
function does_pw_contain_sequential_chars($pw) {
	
	
		// a much simplified version.
		
		var disallowed = new Array(
			'qwer',
			'wert',
			'erty',
			'rtyu',
			'tyui',
			'yuio',
			'uiop',
			'iop[',
			'op[]',
			'p[]\\',
			'asdf',
			'sdfg',
			'dfgh',
			'fghj',
			'ghjk',
			'hjkl',
			'jkl;',
			"kl;'",
			'zxcv',
			'xcvb',
			'cvbn',
			'vbnm',
			'bnm,',
			'nm,.',
			'm,./',
			'1234',
			'2345',
			'3456',
			'4567',
			'5678',
			'6789',
			'7890',
			'0123',
			'rewq',
			'fdsa',
			'vcxz',
			'gfds',
			'hgfd',
			'jhgf',
			'bvxc',
			'nbvc',
			'!@#$',
			'@#$%',
			'#$%^',
			'$%^&',
			'%^&*',
			'^&*(',
			'$#@!',
			'+_)(',
			'-*/',
			'/*-',
			'a1b2',
			'abc',
			'xyz',
			'azerty'
			
		);
	
		var lower = pw.toLowerCase();

		for(var i=0; i<disallowed.length; i++){
		
			var str = disallowed[i].toString();
			if(lower.indexOf(str) != -1){
				return true;
			}
		}
	

	return false;
	}
	
	
	// I rewrote this for simplicity.
	// it's far from exhaustive.
	// but it now includes some of the worst passwords of 2013:
	// http://splashdata.com/press/worstpasswords2013.htm
	function is_common_dictionary_word(){
		var banned_words = new Array('password', 'business', 'customer', 'jesus', 'love', 'client', 'meeting', 'appointment', 'admin', 'pass', 'word', 'random', 'website',
		'monkey', 'letmein', 'princess', 'trust', 'shadow', 'sunshine', 'secret', 'change');
		
		if(test_against_banned_word_list(banned_words)){
			return true;
		}else{
			return false;
		}
	}
	
	
	// I've moved the logic of is_common_dictionary_word into its own function
	// so I can re-use it in the check against the e-mail address
	function test_against_banned_word_list(banned_words){
		
		var test = convert_leet();
		
		for(var i=0; i<banned_words.length; i++){
			if(test.indexOf(banned_words[i]) != -1){
				return true;
			}
		}
		
		// and again
		test = strip_nonword_characters();
		
		for(var i=0; i<banned_words.length; i++){
			if(test.indexOf(banned_words[i]) != -1){
				return true;
			}
		}		
		
		return false;		
		
	}
	
	
	// converts "leet speak" to letters
	// then removes non-word characters.
	function convert_leet(){
	
		var lower = pw.toLowerCase();
	
		var leet = new Array('!', '@', '$', '+', '1', '3', '4', '5', '6', '9', '0');
		var normal = new Array('i', 'a', 's', 't', 'l', 'e', 'a', 's', 'b', 'g', 'o');
		
		return lower.str_replace(leet, normal);
		
		}

	function strip_nonword_characters(){
	
		var lower = pw.toLowerCase();
		
		return lower.replace(/[^\p{L}\p{Nd}]/g, '');	
	
	}
	
}
