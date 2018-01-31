<?php
/**
 *  Class to Scan Websites for Malware, Updates, Added or Removed Files
 */

class phpWebScan {
    private $infected_files = array();
    private $scanned_files  = array();
    private $fileindex      = array();
    private $modified       = array();
    private $oldfileindex;
    private $lastscan;

    /**
     * Function to scan a directory for files or more directories
     * @string $dir The directory to scan
     */
    function scan($dir) {
        // If having issues with timing out uncomment this line
        // set_time_limit(60);

        $this->scanned_files[] = $dir;

        $files = scandir($dir);

        // if there is no array then stop
        if(!is_array($files)) {
            throw new Exception('Unable to scan directory ' . $dir . '.  Please make sure proper permissions have been set.');
        }

        // loop through the DIR and check for files or Directories
        foreach($files as $file) {
            if(is_file($dir.'/'.$file) && !in_array($dir.'/'.$file,$this->scanned_files)) {
                // grab the cile contents and check for malware injection
                $this->check(file_get_contents($dir.'/'.$file),$dir.'/'.$file);
            } elseif(is_dir($dir.'/'.$file) && substr($file,0,1) != '.') {
                // do not scan scanner log files as they change every scan
                if($file != 'scanner-logs')
                    $this->scan($dir.'/'.$file);
            }
        }
    }

    /**
     * Function to check the file contents for injections
     * @string $contents Content of the file
     * @string $file     Filename being checked
     */
    function check($contents,$file) {
        $this->scanned_files[] = $file;
        $this->fileindex[]     = $file;

        // check for injection
        if(preg_match('/eval\((base64|eval|\$_|\$\$|\$[A-Za-z_0-9\{]*(\(|\{|\[))/i',$contents)) {
            $this->infected_files[] = $file;
            echo 'Possible Infected File: (use of eval) '.$file.'<br>';
        }

        /* if you are looking for other injected code add here */
        if(preg_match('/x65\/li\x6eweb/' , $contents)){
            $this->infected_files[] = $file;
            echo 'Possible Infected File: (use of x65 or x6eweb) '.$file.'<br>';
        }

        // check for modification
        if(filemtime($file) > $this->lastscan){
            $this->modified[] = '<strong>'.$file.'</strong> modified '.date ("F d Y H:i:s", filemtime($file));
        }
    }

    /**
     * Function to create a message containing results of scan
     */
    function sendalert() {
        $updateList = false;

        // files count
        $message = '<li>';
        $message .= '<h2>Files Scanned</h2>';
        $message .= ''.number_format(count($this->fileindex)).' files during this scanned <br>';
        $message .= ''.number_format(count($this->oldfileindex)).' files during last scanned <br><div class="hr"></div>';
        $message .= '</li>';

        // infected file list
        if(count($this->infected_files) != 0) {
            $detected = true;
            $message .= '<li>';
            $message .= '<h2>Malicious Code Found</h2>';
            $message .= 'The following files have raised a red flag: <br>';
            foreach($this->infected_files as $inf) {
                $inf = str_replace($_SERVER['DOCUMENT_ROOT'], '', $inf);
                $message .= '<span class="code red">  -  '.$inf.' </span><br>';
            }
            $message .= '</li>';
        } else {
            $detected = false;
            $message .= '<li>';
            $message .= '<strong>Looks Clean</strong> <br> No files detected to have infected PHP that could infiltrate <strong>'.$_SERVER['HTTP_HOST'].'</strong>. <br> Moving forward... <div class="hr"></div>';
            $message .= '</li>';
        }

        // files added
        $difference = array_diff($this->fileindex, $this->oldfileindex);
        if(count($difference) > 0){
            // set flag for file write
            $updateList = true;

            $message .= '<li>';
            $message .= '<h2>Files Added Since Last Scan</h2>';
            foreach ($difference as $added) {
                $added = str_replace($_SERVER['DOCUMENT_ROOT'], '', $added);
                $message .= '<span class="line">'.$added.'</span><br>';
            }
            $message .= '</li>';
        } else {
            $message .= '<li>';
            $message .= '<span>No Files Have Been Added Since Last Scan</span>';
            $message .= '<div class="hr"></div>';
            $message .= '</li>';
        }

        // files Removed
        $removed = array_diff($this->oldfileindex, $this->fileindex);
        if(count($removed) > 0){
            // set flag for file write
            $updateList = true;

            // add results to message
            $message .= '<li>';
            $message .= '<h2>Files Removed Since Last Scan</h2>';
            foreach ($removed as $deleted) {
                $deleted = str_replace($_SERVER['DOCUMENT_ROOT'], '', $deleted);
                $message .= '<span class="line">'.$deleted.'</span><br>';
            }
            $message .= '<div class="hr"></div>';
            $message .= '</li>';
        } else {
            $message .= '<li>';
            $message .= '<span>No Files Have Been Removed Since Last Scan</span>';
            $message .= '<div class="hr"></div>';
            $message .= '</li>';
        }

        // files modified
        if(count($this->modified) > 0) {
            // set flag for file write
            $updateList = true;

            $message .= '<li>';
            $message .= '<h2>Files Modified Since Last Scan</h2>';
            foreach ($this->modified as $modded) {
                $modded = str_replace($_SERVER['DOCUMENT_ROOT'], '', $modded);
                $message .= '<span class="line">'.$modded.'</span><br>';
            }
            $message .= '<div class="hr"></div>';
            $message .= '</li>';
        } else {
            $message .= '<li>';
            $message .= '<span>No Files Have Been Modified Since Last Scan</span>';
            $message .= '<div class="hr"></div>';
            $message .= '</li>';
        }

        // do we need to create an updated file list
        if($updateList == true){
            // create an update file list
            self::writeFile();
        }

        $header = '
        <!doctype html>
        <html lang="en">
        	<head>
        		<meta charset="utf-8" />
        		<title>Website Scan : '.$_SERVER['HTTP_HOST'].'</title>
        		<style>
        			body {
        				font:15px/25px \'Open Sans\', \'Helvetica Neue\', \'DejaVu Sans\', Arial, sans-serif;
        				background:#FFF;
        				color:#333;
        				margin: 2em;
        			}

              h2 {
                margin: 10px 0px 5px 0px;
              }

        			a, a:visited {
        				color:#4DBCE9;
        			}

        			a:hover, a:active {
        				color:#26ADE4;
        			}

        			.code {
        				background:#D1E751;
        				border-radius:4px;
        				padding: 2px 6px;
        			}

              .codered {
                color: #CD5A68;
              }

              .codegreen {
                color: #D1E751;
              }

              ul {
                list-style: none;
                margin: 0px;
                padding:0px;
              }

              ul li {
                padding: 10px 0px;
                border-top: 1px solid #dddddd;
              }
        		</style>
        	</head>
        	<body>

          <h1>'.$_SERVER['HTTP_HOST'].' Scanner</h1>
          <ul>
          ';

        $footer = '
        </ul>
        </body>
        </html>';


        //  class="'.($detected == true ? 'codered' : 'codegreen').'"

        // $headers = "MIME-Version: 1.0" . "\r\n";
        // $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
        // // More headers
        // $headers .= 'From: Website Scan <'.FROM_EMAIL.'>' . "\r\n";

        // mail(EMAIL_ALERT, 'Website Scan results', $header.$message.$footer, $headers);
        echo Mailer::mail($_SERVER['HTTP_HOST'], $header.$message.$footer);

        // echo $header.$message.$footer;

        // log record
        self::logResults($message);
    }

    /**
     * Function will create a file containing a serialiazed array of files scanned
     */
    function writeFile() {
        // debug. Uncomment to get a fresh file list
        // $this->freshclean();

        $data = serialize($this->fileindex);
        $fopen = fopen('scanner-logs/scannerfiles.txt', 'w+');
        fwrite($fopen, $data);
        fclose($fopen);
    }

    /**
     * Function to read the previously canned filenames and unserialize them to an array
     * It will also return the last time a file list was created
     */
    function readFile() {
        $this->oldfileindex = unserialize(file_get_contents('scanner-logs/scannerfiles.txt'));
        $this->lastscan = filemtime('scanner-logs/scannerfiles.txt');
    }

    /**
     * Function to help with debugging. Will clear the fileindex array.
     */
    function freshclean() {
        unset($this->fileindex);
        $this->fileindex[] = '';
    }

    /**
     * Function to log results for future reading
     * @string $message Records a log of the results
     */
    function logResults($message) {
        $fopen = fopen('scanner-logs/scan-results-'.time().'.log', 'w+');
        fwrite($fopen, $message);
        fclose($fopen);
    }
}
