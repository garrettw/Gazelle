<?php
//-----------------------------------------------------------------------------------
/////////////////////////////////////////////////////////////////////////////////////
/*//-- MySQL wrapper class ----------------------------------------------------------

This class provides an interface to mysqli. You should always use this class instead
of the mysql/mysqli functions, because this class provides debugging features and a
bunch of other cool stuff.

Everything returned by this class is automatically escaped for output. This can be
turned off by setting $Escape to false in next_record or to_array.

//--------- Basic usage -------------------------------------------------------------

* Creating the object.

require(SERVER_ROOT.'/classes/mysql.class.php');
$DB = NEW DB_MYSQL;
-----

* Making a query

$DB->query("
    SELECT *
    FROM table...");

    Is functionally equivalent to using mysqli_query("SELECT * FROM table...")
    Stores the result set in $this->QueryID
    Returns the result set, so you can save it for later (see set_query_id())
-----

* Getting data from a query

$array = $DB->next_record();
    Is functionally equivalent to using mysqli_fetch_array($ResultSet)
    You do not need to specify a result set - it uses $this-QueryID
-----

//--------- Advanced usage ---------------------------------------------------------

* The conventional way of retrieving a row from a result set is as follows:

list($All, $Columns, $That, $You, $Select) = $DB->next_record();
-----

* This is how you loop over the result set:

while (list($All, $Columns, $That, $You, $Select) = $DB->next_record()) {
    echo "Do stuff with $All of the ".$Columns.$That.$You.$Select;
}
-----

* There are also a couple more mysqli functions that have been wrapped. They are:

record_count()
    Wrapper to mysqli_num_rows()

affected_rows()
    Wrapper to mysqli_affected_rows()

inserted_id()
    Wrapper to mysqli_insert_id()

close
    Wrapper to mysqli_close()
-----

* And, of course, a few handy custom functions.

to_array($Key = false)
    Transforms an entire result set into an array (useful in situations where you
    can't order the rows properly in the query).

    If $Key is set, the function uses $Key as the index (good for looking up a
    field). Otherwise, it uses an iterator.

    For an example of this function in action, check out forum.php.

collect($Key)
    Loops over the result set, creating an array from one of the fields ($Key).
    For an example, see forum.php.

set_query_id($ResultSet)
    This class can only hold one result set at a time. Using set_query_id allows
    you to set the result set that the class is using to the result set in
    $ResultSet. This result set should have been obtained earlier by using
    $DB->query().

    Example:

    $FoodRS = $DB->query("
            SELECT *
            FROM food");
    $DB->query("
        SELECT *
        FROM drink");
    $Drinks = $DB->next_record();
    $DB->set_query_id($FoodRS);
    $Food = $DB->next_record();

    Of course, this example is contrived, but you get the point.


-------------------------------------------------------------------------------------
*///---------------------------------------------------------------------------------

if (!extension_loaded('mysqli')) {
    die('Mysqli Extension not loaded.');
}

//TODO: revisit access levels once Drone is replaced by ZeRobot
class DB_MYSQL {
    /** @var mysqli|bool */
    public $LinkID = false;
    /** @var mysqli_result|bool */
    protected $QueryID = false;
    protected $Record = [];
    protected $Row;
    protected $Errno = 0;
    protected $Error = '';

    protected $PreparedQuery = null;
    protected $Statement = null;

    public $Queries = [];
    public $Time = 0.0;

    protected $Database = '';
    protected $Server = '';
    protected $User = '';
    protected $Pass = '';
    protected $Port = 0;
    protected $Socket = '';

    function __construct($Database = SQLDB, $User = SQLLOGIN, $Pass = SQLPASS, $Server = SQLHOST, $Port = SQLPORT, $Socket = SQLSOCK) {
        $this->Database = $Database;
        $this->Server = $Server;
        $this->User = $User;
        $this->Pass = $Pass;
        $this->Port = $Port;
        $this->Socket = $Socket;
    }

    function halt($Msg) {
        global $Debug, $argv;
        $DBError = 'MySQL: '.strval($Msg).' SQL error: '.strval($this->Errno).' ('.strval($this->Error).')';
        if ($this->Errno == 1194) {
            send_irc('PRIVMSG '.ADMIN_CHAN.' :'.$this->Error);
        }
        /*if ($this->Errno == 1194) {
            preg_match("Table '(\S+)' is marked as crashed and should be repaired", $this->Error, $Matches);
        } */
        $Debug->analysis('!dev DB Error', $DBError, 3600 * 24);
        if (DEBUG_MODE || check_perms('site_debug') || isset($argv[1])) {
            echo '<pre>'.display_str($DBError).'</pre>';
            if (DEBUG_MODE || check_perms('site_debug')) {
                print_r($this->Queries);
            }
            die();
        } else {
            error('-1');
        }
    }

    function connect() {
        if (!$this->LinkID) {
            $this->LinkID = mysqli_connect($this->Server, $this->User, $this->Pass, $this->Database, $this->Port, $this->Socket); // defined in config.php
            if (!$this->LinkID) {
                $this->Errno = mysqli_connect_errno();
                $this->Error = mysqli_connect_error();
                $this->halt('Connection failed (host:'.$this->Server.':'.$this->Port.')');
            }
        }
    }

    private function setup_query() {
        /*
         * If there was a previous query, we store the warnings. We cannot do
         * this immediately after mysqli_query because mysqli_insert_id will
         * break otherwise due to mysqli_get_warnings sending a SHOW WARNINGS;
         * query. When sending a query, however, we're sure that we won't call
         * mysqli_insert_id (or any similar function, for that matter) later on,
         * so we can safely get the warnings without breaking things.
         * Note that this means that we have to call $this->warnings manually
         * for the last query!
         */
        if ($this->QueryID) {
            $this->warnings();
        }

        $this->connect();
    }

    /**
     * Runs a raw query assuming pre-sanitized input. However, attempting to self sanitize (such
     * as via db_string) is still not as safe for using prepared statements so for queries
     * involving user input, you really should not use this function (instead opting for
     * prepared_query) {@See DB_MYSQL::prepared_query}
     *
     * When running a batch of queries using the same statement
     * with a variety of inputs, it's more performant to reuse the statement
     * with {@see DB_MYSQL::prepare} and {@see DB_MYSQL::execute}
     *
     * @return mysqli_result|bool Returns a mysqli_result object
     *                            for successful SELECT queries,
     *                            or TRUE for other successful DML queries
     *                            or FALSE on failure.
     *
     * @param $Query
     * @param int $AutoHandle
     * @return mysqli_result|bool
     */
    function query($Query, $AutoHandle=1) {
        $this->setup_query();
        $LinkID = &$this->LinkID;

        $Closure = function() use ($LinkID, $Query) {
            return mysqli_query($this->LinkID, $Query);
        };

        return $this->attempt_query($Query, $Closure, $AutoHandle);
    }

    /**
     * Prepares an SQL statement for execution with data.
     *
     * Normally, you'll most likely just want to be using
     * DB_MYSQL::prepared_query to call both DB_MYSQL::prepare
     * and DB_MYSQL::execute for one-off queries, you can use
     * this separately in the case where you plan to be running
     * this query repeatedly while just changing the bound
     * parameters (such as if doing a bulk update or the like).
     *
     * @return mysqli_stmt|bool Returns a statement object
     *                          or FALSE if an error occurred.
     */
    function prepare($Query) {
        $this->setup_query();
        $this->PreparedQuery = $Query;
        $this->Statement = $this->LinkID->prepare($Query);
        if ($this->Statement === false) {
            $this->halt("Invalid Query: [$Query] " . mysqli_error($this->LinkID));
        }
        return $this->Statement;
    }

    /**
     * Bind variables to our last prepared query and execute it.
     *
     * Variables that are passed into the function will have their
     * type automatically set for how to bind it to the query (either
     * integer (i), double (d), or string (s)).
     *
     * @param  array $Parameters,... variables for the query
     * @return mysqli_result|bool Returns a mysqli_result object
     *                            for successful SELECT queries,
     *                            or TRUE for other successful DML queries
     *                            or FALSE on failure.
     */
    function execute(...$Parameters) {
        /** @var mysqli_stmt $Statement */
        $Statement = &$this->Statement;

        if (count($Parameters) > 0) {
            $Binders = "";
            foreach ($Parameters as $Parameter) {
                if (is_integer($Parameter)) {
                    $Binders .= "i";
                }
                elseif (is_double($Parameter)) {
                    $Binders .= "d";
                }
                else {
                    $Binders .= "s";
                }
            }
            $Statement->bind_param($Binders, ...$Parameters);
        }

        $Closure = function() use ($Statement) {
            $Statement->execute();
            return $Statement->get_result();
        };

        $Query = "$this->PreparedQuery\n";
        foreach ($Parameters as $key => $value) {
            $Query .= "$key => $value\n";
        }


        return $this->attempt_query($Query, $Closure);
    }

    /**
     * Prepare and execute a prepared query returning the result set.
     *
     * Utility function that wraps DB_MYSQL::prepare and DB_MYSQL::execute
     * as most times, the query is going to be one-off and this will save
     * on keystrokes. If you do plan to be executing a prepared query
     * multiple times with different bound parameters, you'll want to call
     * the two functions separately instead of this function.
     *
     * @param $Query
     * @param array ...$Parameters
     * @return bool|mysqli_result
     */
    function prepared_query($Query, ...$Parameters) {
        $this->prepare($Query);
        return $this->execute(...$Parameters);
    }

    function prepared_query_array($Query, array $args) {
        $this->prepare($Query);
        $param = [];
        $bind = '';
        $n = count($args);
        for ($i = 0; $i < $n; ++$i) {
            if (is_integer($args[$i])) {
                $bind .= 'i';
            }
            elseif (is_double($args[$i])) {
                $bind .= 'd';
            }
            else {
                $bind .= 's';
            }
            $param[] = &$args[$i];
        }
        $refbind = &$bind;
        array_unshift($param, $refbind);
        $stmt = &$this->Statement;
        call_user_func_array([$this->Statement, "bind_param"], $param);

        return $this->attempt_query(
            $Query,
            function() use ($stmt) {
                $stmt->execute();
                return $stmt->get_result();
            }
        );
    }

    private function attempt_query($Query, Callable $Closure, $AutoHandle=1) {
        global $Debug;
        $QueryStartTime = microtime(true);
        // In the event of a MySQL deadlock, we sleep allowing MySQL time to unlock, then attempt again for a maximum of 5 tries
        for ($i = 1; $i < 6; $i++) {
            $this->QueryID = $Closure();
            if (!in_array(mysqli_errno($this->LinkID), array(1213, 1205))) {
                break;
            }
            $Debug->analysis('Non-Fatal Deadlock:', $Query, 3600 * 24);
            trigger_error("Database deadlock, attempt $i");

            sleep($i * rand(2, 5)); // Wait longer as attempts increase
        }
        $QueryEndTime = microtime(true);
        // Kills admin pages, and prevents Debug->analysis when the whole set exceeds 1 MB
        if (($Len = strlen($Query))>16384) {
            $Query = substr($Query, 0, 16384).'... '.($Len-16384).' bytes trimmed';
        }
        $this->Queries[] = array($Query, ($QueryEndTime - $QueryStartTime) * 1000, null);
        $this->Time += ($QueryEndTime - $QueryStartTime) * 1000;

        // Update/Insert/etc statements for prepared queries don't return a QueryID,
        // but mysqli_errno is also going to be 0 for no error
        $this->Errno = mysqli_errno($this->LinkID);
        if (!$this->QueryID && $this->Errno !== 0) {
            $this->Error = mysqli_error($this->LinkID);

            if ($AutoHandle) {
                $this->halt("Invalid Query: $Query");
            } else {
                return $this->Errno;
            }
        }

        $this->Row = 0;
        if ($AutoHandle) {
            return $this->QueryID;
        }
    }

    function query_unb($Query) {
        $this->connect();
        mysqli_real_query($this->LinkID, $Query);
    }

    function inserted_id() {
        if ($this->LinkID) {
            return mysqli_insert_id($this->LinkID);
        }
    }

    function next_record($Type = MYSQLI_BOTH, $Escape = true, $Reverse = false) {
        // $Escape can be true, false, or an array of keys to not escape
        // If $Reverse is true, then $Escape is an array of keys to escape
        if ($this->LinkID) {
            $this->Record = mysqli_fetch_array($this->QueryID, $Type);
            $this->Row++;
            if (!is_array($this->Record)) {
                $this->QueryID = false;
            } elseif ($Escape !== false) {
                $this->Record = Misc::display_array($this->Record, $Escape, $Reverse);
            }
            return $this->Record;
        }
        return null;
    }

    /**
     * Fetches next record from the result set of the previously executed query.
     *
     * Utility around next_record where we just return the array as MYSQLI_BOTH
     * and require the user to explicitly define which columns to define (as opposed
     * to all columns always being escaped, which is a bad sort of lazy). Things that
     * need to be escaped are strings that users input (with any characters) and
     * are not displayed inside a textarea or input field.
     *
     * @param mixed  $Escape Boolean true/false for escaping entire/none of query
     *                          or can be an array of array keys for what columns to escape
     * @return array next result set if exists
     */
    function fetch_record(...$Escape) {
        if (count($Escape) === 1 && $Escape[0] === true) {
            $Escape = true;
        }
        elseif (count($Escape) === 0) {
            $Escape = false;
        }
        return $this->next_record(MYSQLI_BOTH, $Escape, true);
    }

    function close() {
        if ($this->LinkID) {
            if (!mysqli_close($this->LinkID)) {
                $this->halt('Cannot close connection or connection did not open.');
            }
            $this->LinkID = false;
        }
    }

    /*
     * returns an integer with the number of rows found
     * returns a string if the number of rows found exceeds MAXINT
     */
    function record_count() {
        if ($this->QueryID) {
            return mysqli_num_rows($this->QueryID);
        }
    }

    /*
     * returns true if the query exists and there were records found
     * returns false if the query does not exist or if there were 0 records returned
     */
    function has_results() {
        return ($this->QueryID && $this->record_count() !== 0);
    }

    function affected_rows() {
        if ($this->LinkID) {
            return $this->LinkID->affected_rows;
        }
    }

    function info() {
        return mysqli_get_host_info($this->LinkID);
    }

    // You should use db_string() instead.
    function escape_str($Str) {
        $this->connect();
        if (is_array($Str)) {
            trigger_error('Attempted to escape array.');
            return '';
        }
        return mysqli_real_escape_string($this->LinkID, $Str);
    }

    // Creates an array from a result set
    // If $Key is set, use the $Key column in the result set as the array key
    // Otherwise, use an integer
    function to_array($Key = false, $Type = MYSQLI_BOTH, $Escape = true) {
        $Return = [];
        while ($Row = mysqli_fetch_array($this->QueryID, $Type)) {
            if ($Escape !== false) {
                $Row = Misc::display_array($Row, $Escape);
            }
            if ($Key !== false) {
                $Return[$Row[$Key]] = $Row;
            } else {
                $Return[] = $Row;
            }
        }
        mysqli_data_seek($this->QueryID, 0);
        return $Return;
    }

    //  Loops through the result set, collecting the $ValField column into an array with $KeyField as keys
    function to_pair($KeyField, $ValField, $Escape = true) {
        $Return = [];
        while ($Row = mysqli_fetch_array($this->QueryID)) {
            if ($Escape) {
                $Key = display_str($Row[$KeyField]);
                $Val = display_str($Row[$ValField]);
            } else {
                $Key = $Row[$KeyField];
                $Val = $Row[$ValField];
            }
            $Return[$Key] = $Val;
        }
        mysqli_data_seek($this->QueryID, 0);
        return $Return;
    }

    //  Loops through the result set, collecting the $Key column into an array
    function collect($Key, $Escape = true) {
        $Return = [];
        while ($Row = mysqli_fetch_array($this->QueryID)) {
            $Return[] = $Escape ? display_str($Row[$Key]) : $Row[$Key];
        }
        mysqli_data_seek($this->QueryID, 0);
        return $Return;
    }

    function set_query_id(&$ResultSet) {
        $this->QueryID = $ResultSet;
        $this->Row = 0;
    }

    function get_query_id() {
        return $this->QueryID;
    }

    function beginning() {
        mysqli_data_seek($this->QueryID, 0);
        $this->Row = 0;
    }

    /**
     * This function determines whether the last query caused warning messages
     * and stores them in $this->Queries.
     */
    function warnings() {
        $Warnings = [];
        if ($this->LinkID !== false && mysqli_warning_count($this->LinkID)) {
            $e = mysqli_get_warnings($this->LinkID);
            do {
                if ($e->errno == 1592) {
                    // 1592: Unsafe statement written to the binary log using statement format since BINLOG_FORMAT = STATEMENT.
                    continue;
                }
                $Warnings[] = 'Code ' . $e->errno . ': ' . display_str($e->message);
            } while ($e->next());
        }
        $this->Queries[count($this->Queries) - 1][2] = $Warnings;
    }

    function begin_transaction() {
        mysqli_begin_transaction($this->LinkID);
    }

    function commit() {
        mysqli_commit($this->LinkID);
    }

    function rollback() {
        mysqli_rollback($this->LinkID);
    }
}
