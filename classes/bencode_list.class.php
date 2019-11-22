<?php

class BENCODE_LIST extends BENCODE2 {
	function enc() {
		if (empty($this->Val)) {
			return 'le';
		}
		$Str = 'l';
		reset($this->Val);
		foreach ($this->Val as $Value) {
			$Str.=$this->encode($Value);
		}
		return $Str.'e';
	}

	// Decode a list
	function dec() {
		$Key = 0; // Array index
		$Length = strlen($this->Str);
		while ($this->Pos < $Length) {
			$Type = $this->Str[$this->Pos];
			// $Type now indicates what type of element we're dealing with
			// It's either an integer (string), 'i' (an integer), 'l' (a list), 'd' (a dictionary), or 'e' (end of dictionary/list)

			if ($Type == 'e') { // End of list
				$this->Pos += 1;
				unset($this->Str); // Since we're finished parsing the string, we don't need to store it anymore. Benchmarked - this makes the parser run way faster.
				return;
			}

			// Decode the bencoded element.
			// This function changes $this->Pos and $this->Val, so you don't have to.
			$this->decode($Type, $Key);
			++$Key;
		}
		return true;
	}
}
