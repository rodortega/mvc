<?php
namespace MVC\Libs;
/*
--------
Filters
--------

sanitize_string                             Remove script tags and encode HTML entities, similar to GUMP::xss_clean();
urlencode                                   Encode url entities
htmlencode                                  Encode HTML entities
sanitize_email                              Remove illegal characters from email addresses
sanitize_numbers                            Remove any non-numeric characters
sanitize_floats                             Remove any non-float characters
trim                                        Remove spaces from the beginning and end of strings
base64_encode                               Base64 encode the input
base64_decode                               Base64 decode the input
sha1                                        Encrypt the input with the secure sha1 algorithm
md5                                         MD5 encode the input
noise_words                                 Remove noise words from string
json_encode                                 Create a json representation of the input
json_decode                                 Decode a json string
rmpunctuation                               Remove all known punctuation characters from a string
basic_tags                                  Remove all layout orientated HTML tags from text. Leaving only basic tags
whole_number                                Ensure that the provided numeric value is represented as a whole number
ms_word_characters                          Converts MS Word special characters [“”‘’–…] to web safe characters
lower_case                                  Converts to lowercase
upper_case                                  Converts to uppercase
slug                                        Creates web safe url slug

--------
Validations
--------

required                                    Ensures the specified key value exists and is not empty.
contains,'value1' 'space separated value'   Verify that a value is contained within the pre-defined value set.
contains_list,value1;value2                 Verify that a value is contained within the pre-defined value set. Error message will NOT show the list of possible values.
doesnt_contain_list,value;value;value       Verify that a value is contained within the pre-defined value set. Error message will NOT show the list of possible values.
valid_email                                 Determine if the provided email has valid format.
max_len,240                                 Determine if the provided value length is less or equal to a specific value.
min_len,4                                   Determine if the provided value length is more or equal to a specific value.
exact_len,5                                 Determine if the provided value length matches a specific value.
alpha                                       Determine if the provided value contains only alpha characters.
alpha_numeric                               Determine if the provided value contains only alpha-numeric characters.
alpha_dash                                  Determine if the provided value contains only alpha characters with dashed and underscores.
alpha_numeric_dash                          Determine if the provided value contains only alpha numeric characters with dashed and underscores.
alpha_numeric_space                         Determine if the provided value contains only alpha numeric characters with spaces.
alpha_space                                 Determine if the provided value contains only alpha characters with spaces.
numeric                                     Determine if the provided value is a valid number or numeric string.
integer                                     Determine if the provided value is a valid integer.
boolean                                     Determine if the provided value is a PHP accepted boolean. Also returns true for strings: yes/no, on/off, 1/0, true/false.
float                                       Determine if the provided value is a valid float.
valid_url                                   Determine if the provided value is a valid URL.
url_exists                                  Determine if a URL exists & is accessible.
valid_ip                                    Determine if the provided value is a valid IP address.
valid_ipv4                                  Determine if the provided value is a valid IPv4 address.
valid_ipv6                                  Determine if the provided value is a valid IPv6 address.
valid_cc                                    Determine if the input is a valid credit card number.
valid_name                                  Determine if the input is a valid human name.
street_address                              Determine if the provided input is likely to be a street address using weak detection.
iban                                        Determine if the provided value is a valid IBAN.
date,d/m/Y                                  Determine if the provided input is a valid date (ISO 8601) or specify a custom format (optional).
min_age,18                                  Determine if the provided input meets age requirement (ISO 8601).
max_numeric,50                              Determine if the provided numeric value is lower or equal to a specific value.
min_numeric,1                               Determine if the provided numeric value is higher or equal to a specific value.
starts,Z                                    Determine if the provided value starts with param.
required_file                               Determine if the file was successfully uploaded.
extension,png;jpg;gif                       Check the uploaded file for extension. Doesn't check mime-type yet.
equalsfield,other_field_name                Determine if the provided field value equals current field value.
guidv4                                      Determine if the provided field value is a valid GUID (v4)
phone_number                                Determine if the provided value is a valid phone number.
regex,/test-[0-9]{3}/                       Custom regex validator.
valid_json_string                           Determine if the provided value is a valid JSON string.
valid_array_size_greater,1                  Check if an input is an array and if the size is more or equal to a specific value.
valid_array_size_lesser,1                   Check if an input is an array and if the size is less or equal to a specific value.
valid_array_size_equal,1                    Check if an input is an array and if the size is equal to a specific value.
valid_twitter                               Determine if the provided value is a valid Twitter account.

--------
Example
--------

$Validator = new Validator();

$_RULES = array(
    'username' => 'required|alpha_numeric|max_len,100|min_len,6',
    'password' => 'required|max_len,100|min_len,6',
    'email' => 'required|valid_email',
    'gender' => 'required|exact_len,1',
    'credit_card' => 'required|valid_cc',
    'bio' => 'required'
);

$_FIELDS = array(
    'username' => 'Name',
    'password' => 'Pass',
    'email' => 'Email Address',
    'gender' => 'Sex',
    'credit_card' => 'Credit Card',
    'bio' => 'Bio'
);

$_FILTERS = array(
    'username' => 'trim|sanitize_string',
    'password' => 'trim|base64_encode',
    'email' => 'trim|sanitize_email',
    'gender' => 'trim'
);

$_POST = $Validator->filter($_POST, $_FILTERS);
$Validator->validate($_POST, $_RULES, $_FIELDS);
*/

use MVC\Libs\Helpers;

class Validator
{
  protected static $instance = null;
  protected $validation_rules = array();
  protected $filter_rules = array();
  protected $errors = array();
  protected static $fields = array();
  protected static $validation_methods = array();
  protected static $validation_methods_errors = array();
  protected static $filter_methods = array();
  public static function get_instance()
  {
    if (self::$instance === null)
    {
      self::$instance = new static ();
    }
    return self::$instance;
  }
  public static $basic_tags = '<br><p><a><strong><b><i><em><img><blockquote><code><dd><dl><hr><h1><h2><h3><h4><h5><h6><label><ul><li><span><sub><sup>';
  public static $en_noise_words = "about,after,all,also,an,and,another,any,are,as,at,be,because,been,before,
                                     being,between,both,but,by,came,can,come,could,did,do,each,for,from,get,
                                     got,has,had,he,have,her,here,him,himself,his,how,if,in,into,is,it,its,it's,like,
                                     make,many,me,might,more,most,much,must,my,never,now,of,on,only,or,other,
                                     our,out,over,said,same,see,should,since,some,still,such,take,than,that,
                                     the,their,them,then,there,these,they,this,those,through,to,too,under,up,
                                     very,was,way,we,well,were,what,where,which,while,who,with,would,you,your,a,
                                     b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,$,1,2,3,4,5,6,7,8,9,0,_";
  protected $fieldCharsToRemove = array(
    '_',
    '-'
  );
  protected $lang;
  public function __construct($lang = 'en')
  {
    $lang_file_location = __DIR__ . DIRECTORY_SEPARATOR . 'lang' . DIRECTORY_SEPARATOR . $lang . '.php';
    if (!Helpers::file_exists($lang_file_location))
    {
      throw new \Exception('Language with key "' . $lang . '" does not exist');
    }
    $this->lang = $lang;
  }
  public static function is_valid(array $data, array $validators)
  {
    $gump = self::get_instance();
    $gump->validation_rules($validators);
    if ($gump->run($data) === false)
    {
      return $gump->get_readable_errors(false);
    }
    else
    {
      return true;
    }
  }
  public static function filter_input(array $data, array $filters)
  {
    $gump = self::get_instance();
    return $gump->filter($data, $filters);
  }
  public function __toString()
  {
    return $this->get_readable_errors(true);
  }
  public static function xss_clean(array $data)
  {
    foreach ($data as $k => $v)
    {
      $data[$k] = filter_var($v, FILTER_SANITIZE_STRING);
    }
    return $data;
  }
  public static function add_validator($rule, $callback, $error_message = null)
  {
    $method = 'validate_' . $rule;
    if (method_exists(__CLASS__, $method) || isset(self::$validation_methods[$rule]))
    {
      throw new \Exception("Validator rule '$rule' already exists.");
    }
    self::$validation_methods[$rule] = $callback;
    if ($error_message)
    {
      self::$validation_methods_errors[$rule] = $error_message;
    }
    return true;
  }
  public static function add_filter($rule, $callback)
  {
    $method = 'filter_' . $rule;
    if (method_exists(__CLASS__, $method) || isset(self::$filter_methods[$rule]))
    {
      throw new \Exception("Filter rule '$rule' already exists.");
    }
    self::$filter_methods[$rule] = $callback;
    return true;
  }
  public static function field($key, array $array, $default = null)
  {
    if (isset($array[$key]))
    {
      return $array[$key];
    }
    return $default;
  }
  public function validation_rules(array $rules = array())
  {
    if (empty($rules))
    {
      return $this->validation_rules;
    }
    $this->validation_rules = $rules;
  }
  public function filter_rules(array $rules = array())
  {
    if (empty($rules))
    {
      return $this->filter_rules;
    }
    $this->filter_rules = $rules;
  }
  public function run(array $data, $check_fields = false, $rules_delimiter = '|', $parameters_delimiters = ',')
  {
    $data = $this->filter($data, $this->filter_rules() , $rules_delimiter, $parameters_delimiters);
    $validated = $this->validate($data, $this->validation_rules() , $rules_delimiter, $parameters_delimiters);
    if ($check_fields === true)
    {
      $this->check_fields($data);
    }
    if ($validated !== true)
    {
      return false;
    }
    return $data;
  }
  private function check_fields(array $data)
  {
    $ruleset = $this->validation_rules();
    $mismatch = array_diff_key($data, $ruleset);
    $fields = array_keys($mismatch);
    foreach ($fields as $field)
    {
      $this->errors[] = array(
        'field' => $field,
        'value' => $data[$field],
        'rule' => 'mismatch',
        'param' => null
      );
    }
  }
  private function is_empty($value)
  {
    return (is_null($value) || $value === '' || (is_array($value) && count($value) === 0));
  }
  public function sanitize(array $input, array $fields = array() , $utf8_encode = true)
  {
    if (empty($fields))
    {
      $fields = array_keys($input);
    }
    $return = array();
    foreach ($fields as $field)
    {
      if (!isset($input[$field]))
      {
        continue;
      }
      else
      {
        $value = $input[$field];
        if (is_array($value))
        {
          $value = $this->sanitize($value);
        }
        if (is_string($value))
        {
          if (strpos($value, "\r") !== false)
          {
            $value = trim($value);
          }
          if (function_exists('iconv') && function_exists('mb_detect_encoding') && $utf8_encode)
          {
            $current_encoding = mb_detect_encoding($value);
            if ($current_encoding != 'UTF-8' && $current_encoding != 'UTF-16')
            {
              $value = iconv($current_encoding, 'UTF-8', $value);
            }
          }
          $value = filter_var($value, FILTER_SANITIZE_STRING);
        }
        $return[$field] = $value;
      }
    }
    return $return;
  }
  public function errors()
  {
    return $this->errors;
  }
  public function validate(array $input, array $ruleset, array $readable_names, $exit_on_error = true, $rules_delimiter = '|', $parameters_delimiter = ',')
  {
    $this->errors = array();
    $this->set_field_names($readable_names);
    foreach ($ruleset as $field => $rules)
    {
      $rules = explode($rules_delimiter, $rules);
      $look_for = array(
        'required_file',
        'required'
      );
      if (count(array_intersect($look_for, $rules)) > 0 || (isset($input[$field])))
      {
        if (isset($input[$field]))
        {
          $input_array = array(
            $input[$field]
          );
        }
        else
        {
          $input_array = array(
            ''
          );
        }
        foreach ($input_array as $value)
        {
          $input[$field] = $value;
          foreach ($rules as $rule)
          {
            $method = null;
            $param = null;
            if (strstr($rule, $parameters_delimiter) !== false)
            {
              $rule = explode($parameters_delimiter, $rule);
              $method = 'validate_' . $rule[0];
              $param = $rule[1];
              $rule = $rule[0];
            }
            else
            {
              $method = 'validate_' . $rule;
            }
            if (is_callable(array(
              $this,
              $method
            )))
            {
              $result = $this->$method($field, $input, $param);
              if (is_array($result))
              {
                if (array_search($result['field'], array_column($this->errors, 'field')) === false)
                {
                  $this->errors[] = $result;
                }
              }
            }
            elseif (isset(self::$validation_methods[$rule]))
            {
              $result = call_user_func(self::$validation_methods[$rule], $field, $input, $param);
              if ($result === false)
              {
                if (array_search($field, array_column($this->errors, 'field')) === false)
                {
                  $this->errors[] = array(
                    'field' => $field,
                    'value' => $input[$field],
                    'rule' => $rule,
                    'param' => $param
                  );
                }
              }
            }
            else
            {
              throw new \Exception("Validator method '$method' does not exist.");
            }
          }
        }
      }
    }
    if (count($this->errors) > 0)
    {
      if ($exit_on_error === true)
      {
        echo json_encode(array(
          "success" => false,
          "errors" => $this->get_errors_array()
        ));
        exit();
      }
      else
      {
        return false;
      }
    }
    else
    {
      return true;
    }
  }
  public static function set_field_name($fieldname, $readable_name)
  {
    self::$fields[$fieldname] = $readable_name;
  }
  public static function set_field_names(array $array)
  {
    foreach ($array as $field => $readable_name)
    {
      self::set_field_name($field, $readable_name);
    }
  }
  public static function set_error_message($rule, $message)
  {
    $gump = self::get_instance();
    self::$validation_methods_errors[$rule] = $message;
  }
  public static function set_error_messages(array $array)
  {
    foreach ($array as $rule => $message)
    {
      self::set_error_message($rule, $message);
    }
  }
  protected function get_messages()
  {
    $lang_file = __DIR__ . DIRECTORY_SEPARATOR . 'lang' . DIRECTORY_SEPARATOR . $this->lang . '.php';
    $messages = require $lang_file;
    if (count(self::$validation_methods_errors) > 0)
    {
      $messages = array_merge($messages, self::$validation_methods_errors);
    }
    return $messages;
  }
  public function get_readable_errors($convert_to_string = false, $field_class = 'gump-field', $error_class = 'gump-error-message')
  {
    if (empty($this->errors))
    {
      return ($convert_to_string) ? null : array();
    }
    $resp = array();
    $messages = $this->get_messages();
    foreach ($this->errors as $e)
    {
      $field = ucwords(str_replace($this->fieldCharsToRemove, chr(32) , $e['field']));
      $param = $e['param'];
      if (array_key_exists($e['field'], self::$fields))
      {
        $field = self::$fields[$e['field']];
        if (array_key_exists($param, self::$fields))
        {
          $param = self::$fields[$e['param']];
        }
      }
      if (isset($messages[$e['rule']]))
      {
        if (is_array($param))
        {
          $param = implode(', ', $param);
        }
        $message = str_replace('{param}', $param, str_replace('{field}', '<span class="' . $field_class . '">' . $field . '</span>', $messages[$e['rule']]));
        $resp[] = $message;
      }
      else
      {
        throw new \Exception('Rule "' . $e['rule'] . '" does not have an error message');
      }
    }
    if (!$convert_to_string)
    {
      return $resp;
    }
    else
    {
      $buffer = '';
      foreach ($resp as $s)
      {
        $buffer .= "<span class=\"$error_class\">$s</span>";
      }
      return $buffer;
    }
  }
  public function get_errors_array($convert_to_string = null)
  {
    if (empty($this->errors))
    {
      return ($convert_to_string) ? null : array();
    }
    $resp = array();
    $messages = $this->get_messages();
    foreach ($this->errors as $e)
    {
      $field = ucwords(str_replace(array(
        '_',
        '-'
      ) , chr(32) , $e['field']));
      $param = $e['param'];
      if (array_key_exists($e['field'], self::$fields))
      {
        $field = self::$fields[$e['field']];
        if (array_key_exists($param, self::$fields))
        {
          $param = self::$fields[$e['param']];
        }
      }
      if (isset($messages[$e['rule']]))
      {
        if (!isset($resp[$e['field']]))
        {
          if (is_array($param))
          {
            $param = implode(', ', $param);
          }
          $message = str_replace('{param}', $param, str_replace('{field}', $field, $messages[$e['rule']]));
          $resp[] = $message;
        }
      }
      else
      {
        throw new \Exception('Rule "' . $e['rule'] . '" does not have an error message');
      }
    }
    return $resp;
  }
  public function filter(array $input, array $filterset, $filters_delimeter = '|', $parameters_delimiter = ',')
  {
    foreach ($filterset as $field => $filters)
    {
      if (!array_key_exists($field, $input))
      {
        continue;
      }
      $filters = explode($filters_delimeter, $filters);
      foreach ($filters as $filter)
      {
        $params = null;
        if (strstr($filter, $parameters_delimiter) !== false)
        {
          $filter = explode($parameters_delimiter, $filter);
          $params = array_slice($filter, 1, count($filter) - 1);
          $filter = $filter[0];
        }
        if (is_array($input[$field]))
        {
          $input_array = & $input[$field];
        }
        else
        {
          $input_array = array(&$input[$field]
          );
        }
        foreach ($input_array as & $value)
        {
          if (is_callable(array(
            $this,
            'filter_' . $filter
          )))
          {
            $method = 'filter_' . $filter;
            $value = $this->$method($value, $params);
          }
          elseif (function_exists($filter))
          {
            $value = $filter($value);
          }
          elseif (isset(self::$filter_methods[$filter]))
          {
            $value = call_user_func(self::$filter_methods[$filter], $value, $params);
          }
          else
          {
            throw new \Exception("Filter method '$filter' does not exist.");
          }
        }
      }
    }
    return $input;
  }
  protected function filter_noise_words($value, $params = null)
  {
    $value = preg_replace('/\s\s+/u', chr(32) , $value);
    $value = " $value ";
    $words = explode(',', self::$en_noise_words);
    foreach ($words as $word)
    {
      $word = trim($word);
      $word = " $word ";
      if (stripos($value, $word) !== false)
      {
        $value = str_ireplace($word, chr(32) , $value);
      }
    }
    return trim($value);
  }
  protected function filter_rmpunctuation($value, $params = null)
  {
    return preg_replace("/(?![.=$'€%-])\p{P}/u", '', $value);
  }
  protected function filter_sanitize_string($value, $params = null)
  {
    return filter_var($value, FILTER_SANITIZE_STRING);
  }
  protected function filter_urlencode($value, $params = null)
  {
    return filter_var($value, FILTER_SANITIZE_ENCODED);
  }
  protected function filter_htmlencode($value, $params = null)
  {
    return filter_var($value, FILTER_SANITIZE_SPECIAL_CHARS);
  }
  protected function filter_sanitize_email($value, $params = null)
  {
    return filter_var($value, FILTER_SANITIZE_EMAIL);
  }
  protected function filter_sanitize_numbers($value, $params = null)
  {
    return filter_var($value, FILTER_SANITIZE_NUMBER_INT);
  }
  protected function filter_sanitize_floats($value, $params = null)
  {
    return filter_var($value, FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
  }
  protected function filter_basic_tags($value, $params = null)
  {
    return strip_tags($value, self::$basic_tags);
  }
  protected function filter_whole_number($value, $params = null)
  {
    return intval($value);
  }
  protected function filter_ms_word_characters($value, $params = null)
  {
    $word_open_double = '“';
    $word_close_double = '”';
    $web_safe_double = '"';
    $value = str_replace(array(
      $word_open_double,
      $word_close_double
    ) , $web_safe_double, $value);
    $word_open_single = '‘';
    $word_close_single = '’';
    $web_safe_single = "'";
    $value = str_replace(array(
      $word_open_single,
      $word_close_single
    ) , $web_safe_single, $value);
    $word_em = '–';
    $web_safe_em = '-';
    $value = str_replace($word_em, $web_safe_em, $value);
    $word_ellipsis = '…';
    $web_ellipsis = '...';
    $value = str_replace($word_ellipsis, $web_ellipsis, $value);
    return $value;
  }
  protected function filter_lower_case($value, $params = null)
  {
    return strtolower($value);
  }
  protected function filter_upper_case($value, $params = null)
  {
    return strtoupper($value);
  }
  protected function filter_slug($value, $params = null)
  {
    $delimiter = '-';
    return strtolower(trim(preg_replace('/[\s-]+/', $delimiter, preg_replace('/[^A-Za-z0-9-]+/', $delimiter, preg_replace('/[&]/', 'and', preg_replace('/[\']/', '', iconv('UTF-8', 'ASCII//TRANSLIT', $value))))) , $delimiter));
  }
  protected function validate_required($field, $input, $param = null)
  {
    if (isset($input[$field]) && ($input[$field] === false || $input[$field] === 0 || $input[$field] === 0.0 || $input[$field] === '0' || !empty($input[$field])))
    {
      return;
    }
    return array(
      'field' => $field,
      'value' => null,
      'rule' => __FUNCTION__,
      'param' => $param
    );
  }
  protected function validate_contains($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    $param = trim(strtolower($param));
    $value = trim(strtolower($input[$field]));
    if (preg_match_all('#\'(.+?)\'#', $param, $matches, PREG_PATTERN_ORDER))
    {
      $param = $matches[1];
    }
    else
    {
      $param = explode(chr(32) , $param);
    }
    if (in_array($value, $param))
    {
      return;
    }
    return array(
      'field' => $field,
      'value' => $value,
      'rule' => __FUNCTION__,
      'param' => $param
    );
  }
  protected function validate_contains_list($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    $param = trim(strtolower($param));
    $value = trim(strtolower($input[$field]));
    $param = explode(';', $param);
    if (in_array($value, $param))
    {
      return;
    }
    else
    {
      return array(
        'field' => $field,
        'value' => $value,
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
  }
  protected function validate_doesnt_contain_list($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    $param = trim(strtolower($param));
    $value = trim(strtolower($input[$field]));
    $param = explode(';', $param);
    if (!in_array($value, $param))
    {
      return;
    }
    else
    {
      return array(
        'field' => $field,
        'value' => $value,
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
  }
  protected function validate_valid_email($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    if (!filter_var($input[$field], FILTER_VALIDATE_EMAIL))
    {
      return array(
        'field' => $field,
        'value' => $input[$field],
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
  }
  protected function validate_max_len($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    if (Helpers::functionExists('mb_strlen'))
    {
      if (mb_strlen($input[$field]) <= (int)$param)
      {
        return;
      }
    }
    else if (strlen($input[$field]) <= (int)$param)
    {
      return;
    }
    return array(
      'field' => $field,
      'value' => $input[$field],
      'rule' => __FUNCTION__,
      'param' => $param
    );
  }
  protected function validate_min_len($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    if (Helpers::functionExists('mb_strlen'))
    {
      if (mb_strlen($input[$field]) >= (int)$param)
      {
        return;
      }
    }
    else if (strlen($input[$field]) >= (int)$param)
    {
      return;
    }
    return array(
      'field' => $field,
      'value' => $input[$field],
      'rule' => __FUNCTION__,
      'param' => $param
    );
  }
  protected function validate_exact_len($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    if (Helpers::functionExists('mb_strlen'))
    {
      if (mb_strlen($input[$field]) == (int)$param)
      {
        return;
      }
    }
    else if (strlen($input[$field]) == (int)$param)
    {
      return;
    }
    return array(
      'field' => $field,
      'value' => $input[$field],
      'rule' => __FUNCTION__,
      'param' => $param
    );
  }
  protected function validate_alpha($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    if (!preg_match('/^([a-zÀÁÂÃÄÅÇÈÉÊËÌÍÎÏÒÓÔÕÖßÙÚÛÜÝàáâãäåçèéêëìíîïðòóôõöùúûüýÿ])+$/i', $input[$field]) !== false)
    {
      return array(
        'field' => $field,
        'value' => $input[$field],
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
  }
  protected function validate_alpha_numeric($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    if (!preg_match('/^([a-z0-9ÀÁÂÃÄÅÇÈÉÊËÌÍÎÏÒÓÔÕÖßÙÚÛÜÝàáâãäåçèéêëìíîïðòóôõöùúûüýÿ])+$/i', $input[$field]) !== false)
    {
      return array(
        'field' => $field,
        'value' => $input[$field],
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
  }
  protected function validate_alpha_dash($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    if (!preg_match('/^([a-zÀÁÂÃÄÅÇÈÉÊËÌÍÎÏÒÓÔÕÖßÙÚÛÜÝàáâãäåçèéêëìíîïðòóôõöùúûüýÿ_-])+$/i', $input[$field]) !== false)
    {
      return array(
        'field' => $field,
        'value' => $input[$field],
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
  }
  protected function validate_alpha_numeric_dash($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    if (!preg_match('/^([a-z0-9ÀÁÂÃÄÅÇÈÉÊËÌÍÎÏÒÓÔÕÖßÙÚÛÜÝàáâãäåçèéêëìíîïðòóôõöùúûüýÿ_-])+$/i', $input[$field]) !== false)
    {
      return array(
        'field' => $field,
        'value' => $input[$field],
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
  }
  protected function validate_alpha_numeric_space($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    if (!preg_match("/^([a-z0-9ÀÁÂÃÄÅÇÈÉÊËÌÍÎÏÒÓÔÕÖßÙÚÛÜÝàáâãäåçèéêëìíîïðòóôõöùúûüýÿ\s])+$/i", $input[$field]) !== false)
    {
      return array(
        'field' => $field,
        'value' => $input[$field],
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
  }
  protected function validate_alpha_space($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    if (!preg_match("/^([a-zÀÁÂÃÄÅÇÈÉÊËÌÍÎÏÒÓÔÕÖßÙÚÛÜÝàáâãäåçèéêëìíîïðòóôõöùúûüýÿ\s])+$/i", $input[$field]) !== false)
    {
      return array(
        'field' => $field,
        'value' => $input[$field],
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
  }
  protected function validate_numeric($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    if (!is_numeric($input[$field]))
    {
      return array(
        'field' => $field,
        'value' => $input[$field],
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
  }
  protected function validate_integer($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    if (filter_var($input[$field], FILTER_VALIDATE_INT) === false || is_bool($input[$field]) || is_null($input[$field]))
    {
      return array(
        'field' => $field,
        'value' => $input[$field],
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
  }
  protected function validate_boolean($field, $input, $param = null)
  {
    if (!isset($input[$field]) || empty($input[$field]) && $input[$field] !== 0)
    {
      return;
    }
    $booleans = array(
      '1',
      1,
      '0',
      0,
      'true',
      true,
      'false',
      false,
      'yes',
      'no',
      'on',
      'off'
    );
    if (in_array($input[$field], $booleans, true))
    {
      return;
    }
    return array(
      'field' => $field,
      'value' => $input[$field],
      'rule' => __FUNCTION__,
      'param' => $param
    );
  }
  protected function validate_float($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    if (filter_var($input[$field], FILTER_VALIDATE_FLOAT) === false)
    {
      return array(
        'field' => $field,
        'value' => $input[$field],
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
  }
  protected function validate_valid_url($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    if (!filter_var($input[$field], FILTER_VALIDATE_URL))
    {
      return array(
        'field' => $field,
        'value' => $input[$field],
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
  }
  protected function validate_url_exists($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    $url = parse_url(strtolower($input[$field]));
    if (isset($url['host']))
    {
      $url = $url['host'];
    }
    if (Helpers::functionExists('checkdnsrr') && Helpers::functionExists('idn_to_ascii'))
    {
      if (Helpers::checkdnsrr(idn_to_ascii($url, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46) , 'A') === false)
      {
        return array(
          'field' => $field,
          'value' => $input[$field],
          'rule' => __FUNCTION__,
          'param' => $param
        );
      }
    }
    elseif (Helpers::gethostbyname($url) == $url)
    {
      return array(
        'field' => $field,
        'value' => $input[$field],
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
  }
  protected function validate_valid_ip($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    if (!filter_var($input[$field], FILTER_VALIDATE_IP) !== false)
    {
      return array(
        'field' => $field,
        'value' => $input[$field],
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
  }
  protected function validate_valid_ipv4($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    if (!filter_var($input[$field], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4))
    {
      return array(
        'field' => $field,
        'value' => $input[$field],
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
  }
  protected function validate_valid_ipv6($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    if (!filter_var($input[$field], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6))
    {
      return array(
        'field' => $field,
        'value' => $input[$field],
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
  }
  protected function validate_valid_cc($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    $number = preg_replace('/\D/', '', $input[$field]);
    if (Helpers::functionExists('mb_strlen'))
    {
      $number_length = mb_strlen($number);
    }
    else
    {
      $number_length = strlen($number);
    }
    if ($number_length == 0)
    {
      return array(
        'field' => $field,
        'value' => $input[$field],
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
    $parity = $number_length % 2;
    $total = 0;
    for ($i = 0;$i < $number_length;++$i)
    {
      $digit = $number[$i];
      if ($i % 2 == $parity)
      {
        $digit *= 2;
        if ($digit > 9)
        {
          $digit -= 9;
        }
      }
      $total += $digit;
    }
    if ($total % 10 == 0)
    {
      return;
    }
    return array(
      'field' => $field,
      'value' => $input[$field],
      'rule' => __FUNCTION__,
      'param' => $param
    );
  }
  protected function validate_valid_name($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    if (!preg_match("/^([a-z \p{L} '-])+$/i", $input[$field]) !== false)
    {
      return array(
        'field' => $field,
        'value' => $input[$field],
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
  }
  protected function validate_street_address($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    $hasLetter = preg_match('/[a-zA-Z]/', $input[$field]);
    $hasDigit = preg_match('/\d/', $input[$field]);
    $hasSpace = preg_match('/\s/', $input[$field]);
    $passes = $hasLetter && $hasDigit && $hasSpace;
    if (!$passes)
    {
      return array(
        'field' => $field,
        'value' => $input[$field],
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
  }
  protected function validate_iban($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    static $character = array(
      'A' => 10,
      'C' => 12,
      'D' => 13,
      'E' => 14,
      'F' => 15,
      'G' => 16,
      'H' => 17,
      'I' => 18,
      'J' => 19,
      'K' => 20,
      'L' => 21,
      'M' => 22,
      'N' => 23,
      'O' => 24,
      'P' => 25,
      'Q' => 26,
      'R' => 27,
      'S' => 28,
      'T' => 29,
      'U' => 30,
      'V' => 31,
      'W' => 32,
      'X' => 33,
      'Y' => 34,
      'Z' => 35,
      'B' => 11
    );
    if (!preg_match("/\A[A-Z]{2}\d{2} ?[A-Z\d]{4}( ?\d{4}){1,} ?\d{1,4}\z/", $input[$field]))
    {
      return array(
        'field' => $field,
        'value' => $input[$field],
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
    $iban = str_replace(' ', '', $input[$field]);
    $iban = substr($iban, 4) . substr($iban, 0, 4);
    $iban = strtr($iban, $character);
    if (bcmod($iban, 97) != 1)
    {
      return array(
        'field' => $field,
        'value' => $input[$field],
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
  }
  protected function validate_date($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    if (!$param)
    {
      $cdate1 = date('Y-m-d', strtotime($input[$field]));
      $cdate2 = date('Y-m-d H:i:s', strtotime($input[$field]));
      if ($cdate1 != $input[$field] && $cdate2 != $input[$field])
      {
        return array(
          'field' => $field,
          'value' => $input[$field],
          'rule' => __FUNCTION__,
          'param' => $param
        );
      }
    }
    else
    {
      $date = \DateTime::createFromFormat($param, $input[$field]);
      if ($date === false || $input[$field] != date($param, $date->getTimestamp()))
      {
        return array(
          'field' => $field,
          'value' => $input[$field],
          'rule' => __FUNCTION__,
          'param' => $param
        );
      }
    }
  }
  protected function validate_min_age($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    $inputDatetime = new DateTime(Helpers::date('Y-m-d', strtotime($input[$field])));
    $todayDatetime = new DateTime(Helpers::date('Y-m-d'));
    $interval = $todayDatetime->diff($inputDatetime);
    $yearsPassed = $interval->y;
    if ($yearsPassed >= $param)
    {
      return;
    }
    return array(
      'field' => $field,
      'value' => $input[$field],
      'rule' => __FUNCTION__,
      'param' => $param
    );
  }
  protected function validate_max_numeric($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    if (is_numeric($input[$field]) && is_numeric($param) && ($input[$field] <= $param))
    {
      return;
    }
    return array(
      'field' => $field,
      'value' => $input[$field],
      'rule' => __FUNCTION__,
      'param' => $param
    );
  }
  protected function validate_min_numeric($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $input[$field] === '')
    {
      return;
    }
    if (is_numeric($input[$field]) && is_numeric($param) && ($input[$field] >= $param))
    {
      return;
    }
    return array(
      'field' => $field,
      'value' => $input[$field],
      'rule' => __FUNCTION__,
      'param' => $param
    );
  }
  protected function validate_starts($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    if (strpos($input[$field], $param) !== 0)
    {
      return array(
        'field' => $field,
        'value' => $input[$field],
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
  }
  protected function validate_required_file($field, $input, $param = null)
  {
    if (!isset($input[$field]))
    {
      return;
    }
    if (is_array($input[$field]) && $input[$field]['error'] === 0)
    {
      return;
    }
    return array(
      'field' => $field,
      'value' => $input[$field],
      'rule' => __FUNCTION__,
      'param' => $param
    );
  }
  protected function validate_extension($field, $input, $param = null)
  {
    if (!isset($input[$field]))
    {
      return;
    }
    if (is_array($input[$field]) && $input[$field]['error'] === 0)
    {
      $param = trim(strtolower($param));
      $allowed_extensions = explode(';', $param);
      $path_info = pathinfo($input[$field]['name']);
      $extension = isset($path_info['extension']) ? $path_info['extension'] : false;
      if ($extension && in_array(strtolower($extension) , $allowed_extensions))
      {
        return;
      }
    }
    return array(
      'field' => $field,
      'value' => $input[$field],
      'rule' => __FUNCTION__,
      'param' => $param
    );
  }
  protected function validate_equalsfield($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    if ($input[$field] == $input[$param])
    {
      return;
    }
    return array(
      'field' => $field,
      'value' => $input[$field],
      'rule' => __FUNCTION__,
      'param' => $param
    );
  }
  protected function validate_guidv4($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    if (preg_match("/\{?[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}\}?$/", $input[$field]))
    {
      return;
    }
    return array(
      'field' => $field,
      'value' => $input[$field],
      'rule' => __FUNCTION__,
      'param' => $param
    );
  }
  protected function validate_phone_number($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    $regex = '/^(\d[\s-]?)?[\(\[\s-]{0,2}?\d{3}[\)\]\s-]{0,2}?\d{3}[\s-]?\d{4}$/i';
    if (!preg_match($regex, $input[$field]))
    {
      return array(
        'field' => $field,
        'value' => $input[$field],
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
  }
  protected function validate_regex($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    $regex = $param;
    if (!preg_match($regex, $input[$field]))
    {
      return array(
        'field' => $field,
        'value' => $input[$field],
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
  }
  protected function validate_valid_json_string($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    if (!is_string($input[$field]) || !is_object(json_decode($input[$field])))
    {
      return array(
        'field' => $field,
        'value' => $input[$field],
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
  }
  protected function validate_valid_array_size_greater($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    if (!is_array($input[$field]) || sizeof($input[$field]) < (int)$param)
    {
      return array(
        'field' => $field,
        'value' => $input[$field],
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
  }
  protected function validate_valid_array_size_lesser($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    if (!is_array($input[$field]) || sizeof($input[$field]) > (int)$param)
    {
      return array(
        'field' => $field,
        'value' => $input[$field],
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
  }
  protected function validate_valid_array_size_equal($field, $input, $param = null)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    if (!is_array($input[$field]) || sizeof($input[$field]) != (int)$param)
    {
      return array(
        'field' => $field,
        'value' => $input[$field],
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
  }
  protected function validate_valid_twitter($field, $input, $param = NULL)
  {
    if (!isset($input[$field]) || $this->is_empty($input[$field]))
    {
      return;
    }
    $json = Helpers::file_get_contents("http://twitter.com/users/username_available?username=" . $input[$field]);
    $result = json_decode($json);
    if ($result->reason !== "taken")
    {
      return array(
        'field' => $field,
        'value' => $input[$field],
        'rule' => __FUNCTION__,
        'param' => $param
      );
    }
  }
}
