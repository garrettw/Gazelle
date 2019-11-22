<?php

class BENCODE_DICT extends BENCODE2 {
	function enc() {
		if (empty($this->Val)) {
			return 'de';
		}
		$Str = 'd';
		reset($this->Val);
		foreach ($this->Val as $Key => $Value) {
			$Str.=strlen($Key).':'.$Key.$this->encode($Value);
		}
		return $Str.'e';
	}

	// Decode a dictionary
	function dec() {
		$Length = strlen($this->Str);
		while ($this->Pos<$Length) {

			if ($this->Str[$this->Pos] == 'e') { // End of dictionary
				$this->Pos += 1;
				unset($this->Str); // Since we're finished parsing the string, we don't need to store it anymore. Benchmarked - this makes the parser run way faster.
				return;
			}

			// Get the dictionary key
			// Length of the key, in bytes
			$KeyLen = $this->Str[$this->Pos];

			// Allow for multi-digit lengths
			while ($this->Str[$this->Pos + 1] != ':' && $this->Pos + 1 < $Length) {
				$this->Pos++;
				$KeyLen.=$this->Str[$this->Pos];
			}
			// $this->Pos is now on the last letter of the key length
			// Adding 2 brings it past that character and the ':' to the beginning of the string
			$this->Pos += 2;

			// Get the name of the key
			$Key = substr($this->Str, $this->Pos, $KeyLen);

			// Move the position past the key to the beginning of the element
			$this->Pos += $KeyLen;
			$Type = $this->Str[$this->Pos];
			// $Type now indicates what type of element we're dealing with
			// It's either an integer (string), 'i' (an integer), 'l' (a list), 'd' (a dictionary), or 'e' (end of dictionary/list)

			// Decode the bencoded element.
			// This function changes $this->Pos and $this->Val, so you don't have to.
			$this->decode($Type, $Key);


		}
		return true;
	}
}
