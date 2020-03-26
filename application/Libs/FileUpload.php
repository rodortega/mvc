<?php
namespace MVC\Libs;

/*
--------
Example
--------

$file = new FileUpload();
$file->setInput("photo");
$file->setDestinationDirectory(UPLOADS);
$file->setMaxFileSize("10M");
$file->setAllowedMimeTypes(array(
  'image/jpeg',
  'image/jpg',
  'image/pjpeg',
  'image/png',
));
$file->setFilename(date('YmdHis') .'_'. random_int(1000, 100000) . ".%s");
$file->allowOverwriting();
$file->save();
if ($file->getStatus())
{
  return $file->getinfo()->destination;
}
else
{
  echo json_encode(array(
    "success" => false,
    "errors" => $file->getinfo()->errors
  ));
}
*/

class FileUpload
{
  private $upload_function = "move_uploaded_file";
  private $file_array = array();
  private $allowOverwriting = false;
  private $input;
  private $destination_directory;
  private $filename;
  private $max_file_size = 0.0;
  private $allowed_mime_types = array();
  private $callbacks = array(
    "before" => null,
    "after" => null
  );
  private $file;
  private $errors;
  private $mime_helping = array(
    'text' => array(
      'text/plain'
    ) ,
    'image' => array(
      'image/jpeg',
      'image/jpg',
      'image/pjpeg',
      'image/png',
      'image/gif'
    ) ,
    'document' => array(
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/vnd.openxmlformats-officedocument.presentationml.presentation',
      'application/vnd.ms-powerpoint',
      'application/vnd.ms-excel',
      'application/vnd.oasis.opendocument.spreadsheet',
      'application/vnd.oasis.opendocument.presentation'
    ) ,
    'video' => array(
      'video/3gpp',
      'video/3gpp',
      'video/x-msvideo',
      'video/avi',
      'video/mpeg4',
      'video/mp4',
      'video/mpeg',
      'video/mpg',
      'video/quicktime',
      'video/x-sgi-movie',
      'video/x-ms-wmv',
      'video/x-flv'
    )
  );
  public function __construct()
  {
    $this->file = array(
      "status" => false,
      "mime" => "",
      "filename" => "",
      "original" => "",
      "size" => 0,
      "sizeFormated" => "0B",
      "destination" => "./",
      "allowed_mime_types" => array() ,
      "log" => array() ,
      "errors" => array(),
      "error" => 0
    );

    $this->destination_directory = dirname(__FILE__) . DIRECTORY_SEPARATOR;
    chdir($this->destination_directory);

    if (isset($_FILES) and is_array($_FILES))
    {
      $this->file_array = $_FILES;
    }
    elseif (isset($HTTP_POST_FILES) and is_array($HTTP_POST_FILES))
    {
      $this->file_array = $HTTP_POST_FILES;
    }
  }
  public function setInput($input)
  {
    if (!empty($input) and (is_string($input) or is_numeric($input)))
    {
      $this->log("Capture set to %s", $input);
      $this->input = $input;
      return true;
    }
    return false;
  }
  public function setFilename($filename)
  {
    if ($this->isFilename($filename))
    {
      $this->log("Filename set to %s", $filename);
      $this->filename = $filename;
      return true;
    }
    return false;
  }
  public function setAutoFilename()
  {
    $this->log("Automatic filename is enabled");
    $this->filename = sha1(mt_rand(1, 9999) . uniqid());
    $this->filename .= time();
    $this->filename .= ".%s";
    $this->log("Filename set to %s", $this->filename);
    return true;
  }
  public function setMaxFileSize($file_size)
  {
    $file_size = $this->sizeInBytes($file_size);
    if (is_numeric($file_size) and $file_size > - 1)
    {
      $size = $this->sizeInBytes(ini_get('upload_max_filesize'));
      $this->log("PHP settings have set the maximum file upload size to %s(%d)", $this->sizeFormat($size) , $size);

      if ($size < $file_size)
      {
        $this->log("WARNING! The PHP configuration allows a maximum size of %s", $this->sizeFormat($size));
        return false;
      }

      $this->log("Maximum allowed size set at %s(%d)", $this->sizeFormat($file_size) , $file_size);

      $this->max_file_size = $file_size;
      return true;
    }
    return false;
  }
  public function setAllowedMimeTypes(array $mimes)
  {
    if (count($mimes) > 0)
    {
      array_map(array(
        $this,
        "setAllowMimeType"
      ) , $mimes);
      return true;
    }

    return false;
  }
  public function setCallbackInput($callback)
  {
    if (is_callable($callback, false))
    {
      $this->callbacks["input"] = $callback;
      return true;
    }
    return false;
  }
  public function setCallbackOutput($callback)
  {
    if (is_callable($callback, false))
    {
      $this->callbacks["output"] = $callback;
      return true;
    }
    return false;
  }
  public function setAllowMimeType($mime)
  {
    if (!empty($mime) and is_string($mime))
    {
      if (preg_match("#^[-\w\+]+/[-\w\+]+$#", $mime))
      {
        $this->log("IMPORTANT! Mime %s enabled", $mime);
        $this->allowed_mime_types[] = strtolower($mime);
        $this->file["allowed_mime_types"][] = strtolower($mime);
        return true;
      }
      else
      {
        return $this->setMimeHelping($mime);
      }
    }
    return false;
  }
  public function setMimeHelping($name)
  {
    if (!empty($mime) and is_string($name))
    {
      if (array_key_exists($name, $this->mime_helping))
      {
        return $this->setAllowedMimeTypes($this->mime_helping[$name]);
      }
    }
    return false;
  }
  public function setUploadFunction($function)
  {
    if (!empty($function) and (is_array($function) or is_string($function)))
    {
      if (is_callable($function))
      {
        $this->log("IMPORTANT! The function for uploading files is set to: %s", $function);
        $this->upload_function = $function;
        return true;
      }
    }
    return false;
  }
  public function clearAllowedMimeTypes()
  {
    $this->allowed_mime_types = array();
    $this->file["allowed_mime_types"] = array();
    return true;
  }
  public function setDestinationDirectory($destination_directory, $create_if_not_exist = false)
  {
    $destination_directory = realpath($destination_directory);
    if (substr($destination_directory, -1) != DIRECTORY_SEPARATOR)
    {
      $destination_directory .= DIRECTORY_SEPARATOR;
    }

    if ($this->isDirpath($destination_directory))
    {
      if ($this->dirExists($destination_directory))
      {
        $this->destination_directory = $destination_directory;
        if (substr($this->destination_directory, -1) != DIRECTORY_SEPARATOR)
        {
          $this->destination_directory .= DIRECTORY_SEPARATOR;
        }
        chdir($destination_directory);
        return true;
      }
      elseif ($create_if_not_exist === true)
      {
        if (mkdir($destination_directory, $this->destination_permissions, true))
        {
          if ($this->dirExists($destination_directory))
          {
            $this->destination_directory = $destination_directory;
            if (substr($this->destination_directory, -1) != DIRECTORY_SEPARATOR)
            {
              $this->destination_directory .= DIRECTORY_SEPARATOR;
            }
            chdir($destination_directory);
            return true;
          }
        }
      }
    }
    return false;
  }
  public function fileExists($file_destination)
  {
    if ($this->isFilename($file_destination))
    {
      return (file_exists($file_destination) and is_file($file_destination));
    }
    return false;
  }
  public function dirExists($path)
  {
    if ($this->isDirpath($path))
    {
      return (file_exists($path) and is_dir($path));
    }
    return false;
  }
  public function isFilename($filename)
  {
    $filename = basename($filename);
    return (!empty($filename) and (is_string($filename) or is_numeric($filename)));
  }
  public function checkMimeType($mime)
  {
    if (count($this->allowed_mime_types) == 0)
    {
      return true;
    }
    return in_array(strtolower($mime) , $this->allowed_mime_types);
  }
  public function getStatus()
  {
    return $this->file["status"];
  }
  public function isDirpath($path)
  {
    if (!empty($path) and (is_string($path) or is_numeric($path)))
    {
      if (DIRECTORY_SEPARATOR == "/")
      {
        return (preg_match('/^[^*?"<>|:]*$/', $path) == 1);
      }
      else
      {
        return (preg_match("/^[^*?\"<>|:]*$/", substr($path, 2)) == 1);
      }
    }
    return false;
  }
  public function allowOverwriting()
  {
    $this->log("Overwrite enabled");
    $this->allowOverwriting = true;
    return true;
  }
  public function getInfo()
  {
    return (object)$this->file;
  }
  public function save()
  {
    if (count($this->file_array) > 0)
    {
      $this->log("Capturing input %s", $this->input);
      if (array_key_exists($this->input, $this->file_array))
      {
        if (empty($this->filename))
        {
          $this->log("Using original filename %s", $this->file_array[$this->input]["name"]);
          $this->filename = $this->file_array[$this->input]["name"];
        }

        $extension = preg_replace("/^[\p{L}\d\s\-\_\.\(\)]*\.([\d\w]+)$/iu", '$1', $this->file_array[$this->input]["name"]);
        $this->filename = sprintf($this->filename, $extension);

        $this->file["mime"] = $this->file_array[$this->input]["type"];
        $this->file["tmp"] = $this->file_array[$this->input]["tmp_name"];
        $this->file["original"] = $this->file_array[$this->input]["name"];
        $this->file["size"] = $this->file_array[$this->input]["size"];
        $this->file["sizeFormated"] = $this->sizeFormat($this->file["size"]);
        $this->file["destination"] = $this->destination_directory . $this->filename;
        $this->file["filename"] = $this->filename;
        $this->file["error"] = $this->file_array[$this->input]["error"];

        if ($this->fileExists($this->destination_directory . $this->filename))
        {
          $this->log("%s file already exists", $this->filename);
          if ($this->allowOverwriting === false)
          {
            $this->log("You don't allow overwriting. Show more about FileUpload::allowOverwriting");
            return false;
          }
          $this->log("The %s file is overwritten", $this->filename);
        }

        if (!empty($this->callbacks["input"]))
        {
          $this->log("Running input callback");
          call_user_func($this->callbacks["input"], (object)$this->file);
        }

        $this->log("Check mime type");
        if (!$this->checkMimeType($this->file["mime"]))
        {
          $this->log("Mime type %s not allowed", $this->file["mime"]);
          $this->log_error("File type %s not allowed", $this->file["mime"]);
          return false;
        }
        $this->log("Mime type %s allowed", $this->file["mime"]);
        if ($this->max_file_size > 0)
        {
          $this->log("Checking file size");

          if ($this->max_file_size < $this->file["size"])
          {
            $this->log("The file exceeds the maximum size allowed(Max: %s; File: %s)", $this->sizeFormat($this->max_file_size) , $this->sizeFormat($this->file["size"]));
            $this->log_error("The file exceeds the maximum size allowed(Max: %s; File: %s)", $this->sizeFormat($this->max_file_size) , $this->sizeFormat($this->file["size"]));
            return false;
          }
        }
        $this->log("Copy tmp file to destination %s", $this->destination_directory);
        $this->log("Using upload function: %s", $this->upload_function);

        $this->file["status"] = call_user_func_array($this->upload_function, array(
          $this->file_array[$this->input]["tmp_name"],
          $this->destination_directory . $this->filename
        ));

        if (!empty($this->callbacks["output"]))
        {
          $this->log("Running output callback");
          call_user_func($this->callbacks["output"], (object)$this->file);
        }
        return $this->file["status"];
      }
    }
  }
  public function log()
  {
    $params = func_get_args();
    $this->file["log"][] = call_user_func_array("sprintf", $params);
    return true;
  }
  public function log_error()
  {
    $params = func_get_args();
    $this->file["errors"][] = call_user_func_array("sprintf", $params);
    return true;
  }
  public function sizeFormat($size, $precision = 2)
  {
    $base = log($size) / log(1024);
    $suffixes = array(
      'B',
      'K',
      'M',
      'G'
    );
    return round(pow(1024, $base - floor($base)) , $precision) . $suffixes[floor($base) ];
  }
  public function sizeInBytes($size)
  {
    $unit = "B";
    $units = array(
      "B" => 0,
      "K" => 1,
      "M" => 2,
      "G" => 3
    );
    $matches = array();
    preg_match("/(?<size>[\d\.]+)\s*(?<unit>b|k|m|g)?/i", $size, $matches);
    if (array_key_exists("unit", $matches))
    {
      $unit = strtoupper($matches["unit"]);
    }
    return (floatval($matches["size"]) * pow(1024, $units[$unit]));
  }
}