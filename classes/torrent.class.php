<?php

class TORRENT extends BENCODE_DICT {
    function dump() {
        // Convenience function used for testing and figuring out how we store the data
        print_r($this->Val);
    }

    function dump_data() {
        // Function which serializes $this->Val for storage
        return base64_encode(serialize($this->Val));
    }

    /*
    To use this, please remove the announce-list unset in make_private and be sure to still set_announce_url for backwards compatibility
    function set_multi_announce() {
        $Trackers = func_get_args();
        $AnnounceList = new BENCODE_LIST([],true);
        foreach ($Trackers as $Tracker) {
            $SubList = new BENCODE_LIST(array($Tracker),true);
            unset($SubList->Str);
            $AnnounceList->Val[] = $SubList;
        }
        $this->Val['announce-list'] = $AnnounceList;
    }
    */

    function set_announce_url($Announce) {
        $this->Val['announce'] = $Announce;
        ksort($this->Val);
    }

    // Returns an array of:
    //     * the files in the torrent
    //    * the total size of files described therein
    function file_list() {
        $FileList = [];
        if (!isset($this->Val['info']->Val['files'])) { // Single file mode
            $TotalSize = $this->Val['info']->Val['length'];
            $FileList[] = array($TotalSize, $this->get_name());
        } else { // Multiple file mode
            $FileNames = [];
            $FileSizes = [];
            $TotalSize = 0;
            $Files = $this->Val['info']->Val['files']->Val;
            if (isset($Files[0]->Val['path.utf-8'])) {
                $PathKey = 'path.utf-8';
            } else {
                $PathKey = 'path';
            }
            foreach ($Files as $File) {
                $FileSize = $File->Val['length'];
                $TotalSize += $FileSize;

                $FileName = ltrim(implode('/', $File->Val[$PathKey]->Val), '/');
                $FileSizes[] = $FileSize;
                $FileNames[] = $FileName;
            }
            natcasesort($FileNames);
            foreach ($FileNames as $Index => $FileName) {
                $FileList[] = array($FileSizes[$Index], $FileName);
            }
        }
        return array($TotalSize, $FileList);
    }

    function get_name() {
        if (isset($this->Val['info']->Val['name.utf-8'])) {
            return $this->Val['info']->Val['name.utf-8'];
        } else {
            return $this->Val['info']->Val['name'];
        }
    }

    function make_private() {
        //----- The following properties do not affect the infohash:

        // anounce-list is an unofficial extension to the protocol
        // that allows for multiple trackers per torrent
        unset($this->Val['announce-list']);

        // Bitcomet & Azureus cache peers in here
        unset($this->Val['nodes']);

        // Azureus stores the dht_backup_enable flag here
        unset($this->Val['azureus_properties']);

        // Remove web-seeds
        unset($this->Val['url-list']);

        // Remove libtorrent resume info
        unset($this->Val['libtorrent_resume']);

        //----- End properties that do not affect the infohash
        if ($this->Val['info']->Val['private']) {
            return true; // Torrent is private
        } else {
            // Torrent is not private!
            // add private tracker flag and sort info dictionary
            $this->Val['info']->Val['private'] = 1;
            ksort($this->Val['info']->Val);
            return false;
        }
    }
}
