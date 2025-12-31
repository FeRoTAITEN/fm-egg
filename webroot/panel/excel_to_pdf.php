<?php
/**
 * Excel to PDF Converter
 * Converts Excel file to PDF and outputs it
 */

// Start session
define('FM_SESSION_ID', 'filemanager');
session_name(FM_SESSION_ID);
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Load auth settings
$use_auth = true;
$auth_users = array(
    'admin' => '$2y$10$/K.hjNr84lLNDt8fTXjoI.DBp6PpeyoJ.mGwrrLuCZfAwfSAGqhOW',
    'user' => '$2y$10$Fg6Dz8oH9fPoZ2jJan5tZuv6Z4Kp7avtQ9bDfrdRntXtPeiMAZyGO'
);

$config_file = __DIR__ . '/config.php';
if (is_readable($config_file)) {
    @include($config_file);
}

if (empty($auth_users)) {
    $use_auth = false;
}

// Check authentication
if ($use_auth) {
    $is_logged = false;
    // Check both session formats for compatibility
    if (isset($_SESSION[FM_SESSION_ID]['logged']) && !empty($_SESSION[FM_SESSION_ID]['logged'])) {
        $is_logged = true;
    } elseif (isset($_SESSION['logged']) && $_SESSION['logged'] === true) {
        $is_logged = true;
    }
    
    if (!$is_logged) {
        header('Content-Type: application/json');
        http_response_code(403);
        die(json_encode(array('success' => false, 'error' => 'Access denied - not logged in')));
    }
}

// Get file path
if (!isset($_GET['file'])) {
    http_response_code(400);
    die('File parameter required');
}

$root_path = __DIR__ . '/../storage';
$root_path = rtrim($root_path, '\\/');
$root_path = str_replace('\\', '/', $root_path);

$relative_path = $_GET['file'];
$file_path = $root_path . '/' . $relative_path;

// Security check
$file_path = realpath($file_path);
$root_real = realpath($root_path);

if (!$file_path || strpos($file_path, $root_real) !== 0) {
    header('Content-Type: application/json');
    http_response_code(403);
    die(json_encode(array('success' => false, 'error' => 'Access denied - invalid path')));
}

if (!file_exists($file_path) || !is_readable($file_path)) {
    header('Content-Type: application/json');
    http_response_code(404);
    die(json_encode(array('success' => false, 'error' => 'File not found')));
}

$ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
if (!in_array($ext, array('xls', 'xlsx'))) {
    header('Content-Type: application/json');
    http_response_code(400);
    die(json_encode(array('success' => false, 'error' => 'Invalid file type')));
}

// Check if we should return raw file for client-side conversion
if (isset($_GET['raw']) && $_GET['raw'] == '1') {
    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: inline; filename="' . basename($file_path) . '"');
    header('Content-Length: ' . filesize($file_path));
    readfile($file_path);
    exit;
}

// Convert Excel to PDF using LibreOffice (pixel-perfect)
function convert_excel_to_pdf_libreoffice($file_path) {
    // Find LibreOffice executable
    $libreoffice_path = trim(shell_exec('which libreoffice 2>/dev/null'));
    if (empty($libreoffice_path)) {
        // Try common paths
        $possible_paths = array(
            '/usr/bin/libreoffice',
            '/usr/local/bin/libreoffice'
        );
        foreach ($possible_paths as $path) {
            if (file_exists($path) && is_executable($path)) {
                $libreoffice_path = $path;
                break;
            }
        }
    }
    
    if (empty($libreoffice_path) || !is_executable($libreoffice_path)) {
        return false;
    }
    
    // Create temporary directory for conversion
    $temp_dir = sys_get_temp_dir() . '/excel_pdf_' . uniqid();
    if (!mkdir($temp_dir, 0755, true)) {
        return false;
    }
    
    try {
        // LibreOffice command for Excel → PDF conversion (pixel-perfect)
        $command = escapeshellarg($libreoffice_path) . 
                   ' --headless' .
                   ' --invisible' .
                   ' --nodefault' .
                   ' --nolockcheck' .
                   ' --nologo' .
                   ' --norestore' .
                   ' --convert-to pdf' .
                   ' --outdir ' . escapeshellarg($temp_dir) .
                   ' ' . escapeshellarg($file_path) .
                   ' 2>&1';
        
        $output = array();
        $return_var = 0;
        exec($command, $output, $return_var);
        
        if ($return_var !== 0) {
            // Cleanup on error
            @array_map('unlink', glob($temp_dir . '/*'));
            @rmdir($temp_dir);
            return false;
        }
        
        // Find generated PDF
        $base_name = basename($file_path);
        $pdf_file = $temp_dir . '/' . preg_replace('/\.(xlsx?|xls)$/i', '.pdf', $base_name);
        
        if (!file_exists($pdf_file)) {
            // Try alternative naming
            $pdf_file = $temp_dir . '/' . pathinfo($base_name, PATHINFO_FILENAME) . '.pdf';
        }
        
        if (!file_exists($pdf_file)) {
            // Cleanup
            @array_map('unlink', glob($temp_dir . '/*'));
            @rmdir($temp_dir);
            return false;
        }
        
        // Read PDF content
        $pdf_content = file_get_contents($pdf_file);
        
        // Cleanup
        @unlink($pdf_file);
        @rmdir($temp_dir);
        
        return $pdf_content;
        
    } catch (Exception $e) {
        // Cleanup on error
        if (is_dir($temp_dir)) {
            @array_map('unlink', glob($temp_dir . '/*'));
            @rmdir($temp_dir);
        }
        return false;
    }
}

// Helper function for theme colors
function get_theme_color($themeIndex) {
    // Excel default theme colors (approximate)
    $themeColors = array(
        0 => array('r' => 0, 'g' => 0, 'b' => 0),           // Black
        1 => array('r' => 255, 'g' => 255, 'b' => 255),     // White
        2 => array('r' => 238, 'g' => 236, 'b' => 225),     // Light Gray
        3 => array('r' => 31, 'g' => 78, 'b' => 121),       // Dark Blue
        4 => array('r' => 79, 'g' => 129, 'b' => 189),      // Blue
        5 => array('r' => 192, 'g' => 80, 'b' => 77),       // Red
        6 => array('r' => 155, 'g' => 187, 'b' => 89),      // Green
        7 => array('r' => 128, 'g' => 100, 'b' => 162),     // Purple
        8 => array('r' => 75, 'g' => 172, 'b' => 198),      // Cyan
        9 => array('r' => 247, 'g' => 150, 'b' => 70),      // Orange
    );
    return isset($themeColors[$themeIndex]) ? $themeColors[$themeIndex] : array('r' => 255, 'g' => 255, 'b' => 255);
}

// Convert Excel to PDF - returns all sheets
function convert_excel_to_pdf($file_path) {
    if (!class_exists('ZipArchive')) {
        return false;
    }
    
    $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
    if ($ext !== 'xlsx') {
        return false;
    }
    
    try {
        $zip = new ZipArchive();
        if ($zip->open($file_path) !== true) {
            return false;
        }
        
        // Read shared strings
        $sharedStrings = array();
        $sharedStringsXml = $zip->getFromName('xl/sharedStrings.xml');
        if ($sharedStringsXml) {
            $xml = @simplexml_load_string($sharedStringsXml);
            if ($xml && isset($xml->si)) {
                foreach ($xml->si as $si) {
                    $text = '';
                    if (isset($si->t)) {
                        $text = (string)$si->t;
                    }
                    $sharedStrings[] = $text;
                }
            }
        }
        
        // Read styles for colors and formatting
        $styles = array('fills' => array(), 'fonts' => array(), 'borders' => array(), 'cellXfs' => array());
        $stylesXml = $zip->getFromName('xl/styles.xml');
        if ($stylesXml) {
            $sXml = @simplexml_load_string($stylesXml);
            if ($sXml) {
                // Read fill colors
                if (isset($sXml->fills->fill)) {
                    foreach ($sXml->fills->fill as $idx => $fill) {
                        $rgb = null;
                        if (isset($fill->patternFill->fgColor->rgb)) {
                            $rgbHex = (string)$fill->patternFill->fgColor->rgb;
                            if (strlen($rgbHex) == 6) {
                                $rgb = array(
                                    'r' => hexdec(substr($rgbHex, 0, 2)),
                                    'g' => hexdec(substr($rgbHex, 2, 2)),
                                    'b' => hexdec(substr($rgbHex, 4, 2))
                                );
                            } elseif (isset($fill->patternFill->fgColor->theme)) {
                                // Handle theme colors - use default colors
                                $themeIndex = (int)$fill->patternFill->fgColor->theme;
                                $rgb = get_theme_color($themeIndex);
                            }
                        }
                        $styles['fills'][$idx] = $rgb;
                    }
                }
                
                // Read fonts
                if (isset($sXml->fonts->font)) {
                    foreach ($sXml->fonts->font as $idx => $font) {
                        $fontData = array(
                            'bold' => isset($font->b),
                            'italic' => isset($font->i),
                            'size' => isset($font->sz['val']) ? (float)$font->sz['val'] : 11,
                            'color' => null
                        );
                        if (isset($font->color->rgb)) {
                            $rgbHex = (string)$font->color->rgb;
                            if (strlen($rgbHex) == 6) {
                                $fontData['color'] = array(
                                    'r' => hexdec(substr($rgbHex, 0, 2)),
                                    'g' => hexdec(substr($rgbHex, 2, 2)),
                                    'b' => hexdec(substr($rgbHex, 4, 2))
                                );
                            }
                        }
                        $styles['fonts'][$idx] = $fontData;
                    }
                }
                
                // Read cellXfs (cell style formatting)
                if (isset($sXml->cellXfs->xf)) {
                    foreach ($sXml->cellXfs->xf as $idx => $xf) {
                        $xfData = array(
                            'fillId' => isset($xf['fillId']) ? (int)$xf['fillId'] : 0,
                            'fontId' => isset($xf['fontId']) ? (int)$xf['fontId'] : 0,
                            'numFmtId' => isset($xf['numFmtId']) ? (int)$xf['numFmtId'] : 0,
                            'alignment' => array(
                                'horizontal' => isset($xf->alignment['horizontal']) ? (string)$xf->alignment['horizontal'] : 'general',
                                'vertical' => isset($xf->alignment['vertical']) ? (string)$xf->alignment['vertical'] : 'bottom'
                            )
                        );
                        $styles['cellXfs'][$idx] = $xfData;
                    }
                }
            }
        }
        
        // Read workbook to get sheet names
        $workbookXml = $zip->getFromName('xl/workbook.xml');
        $sheetNames = array();
        if ($workbookXml) {
            $wbXml = @simplexml_load_string($workbookXml);
            if ($wbXml && isset($wbXml->sheets->sheet)) {
                foreach ($wbXml->sheets->sheet as $sheet) {
                    $sheetNames[] = (string)$sheet['name'];
                }
            }
        }
        
        // If no sheet names found, try to find all worksheets
        if (empty($sheetNames)) {
            for ($i = 1; $i <= 10; $i++) {
                $sheetFile = 'xl/worksheets/sheet' . $i . '.xml';
                if ($zip->locateName($sheetFile) !== false) {
                    $sheetNames[] = 'Sheet' . $i;
                }
            }
        }
        
        // Read all worksheets
        $allSheets = array();
        foreach ($sheetNames as $sheetIndex => $sheetName) {
            $sheetNum = $sheetIndex + 1;
            $worksheetXml = $zip->getFromName('xl/worksheets/sheet' . $sheetNum . '.xml');
            
            if (!$worksheetXml) {
                continue;
            }
            
            // Parse worksheet
            $xml = @simplexml_load_string($worksheetXml);
            if (!$xml || !isset($xml->sheetData)) {
                continue;
            }
            
            // Get sheet data with formatting
            $rows = array();
            $cellStyles = array();
            $maxCol = 0;
            
            if (isset($xml->sheetData->row)) {
                foreach ($xml->sheetData->row as $row) {
                    $rowNum = (int)$row['r'];
                    $rowData = array();
                    $rowStyles = array();
                    
                    if (isset($row->c)) {
                        foreach ($row->c as $cell) {
                            $cellRef = (string)$cell['r'];
                            if (preg_match('/([A-Z]+)(\d+)/', $cellRef, $matches)) {
                                $col = $matches[1];
                                $colNum = column_to_number($col);
                                $maxCol = max($maxCol, $colNum);
                                
                                $value = '';
                                if (isset($cell->v)) {
                                    $cellValue = (string)$cell->v;
                                    if (isset($cell['t']) && (string)$cell['t'] === 's') {
                                        $index = (int)$cellValue;
                                        if (isset($sharedStrings[$index])) {
                                            $value = $sharedStrings[$index];
                                        }
                                    } else {
                                        $value = $cellValue;
                                    }
                                }
                                
                                $rowData[$colNum] = $value;
                                
                                // Read cell style with full formatting
                                $cellStyle = null;
                                if (isset($cell['s'])) {
                                    $styleIndex = (int)$cell['s'];
                                    if (isset($styles['cellXfs'][$styleIndex])) {
                                        $xf = $styles['cellXfs'][$styleIndex];
                                        $fillId = $xf['fillId'];
                                        $fontId = $xf['fontId'];
                                        
                                        $cellStyle = array(
                                            'fillColor' => isset($styles['fills'][$fillId]) ? $styles['fills'][$fillId] : null,
                                            'font' => isset($styles['fonts'][$fontId]) ? $styles['fonts'][$fontId] : null,
                                            'alignment' => $xf['alignment']
                                        );
                                    }
                                }
                                $rowStyles[$colNum] = $cellStyle;
                            }
                        }
                    }
                    
                    for ($i = 0; $i <= $maxCol; $i++) {
                        if (!isset($rowData[$i])) {
                            $rowData[$i] = '';
                        }
                        if (!isset($rowStyles[$i])) {
                            $rowStyles[$i] = null;
                        }
                    }
                    
                    ksort($rowData);
                    ksort($rowStyles);
                    $rows[] = array_values($rowData);
                    $cellStyles[] = array_values($rowStyles);
                }
            }
            
            if (!empty($rows)) {
                $allSheets[] = array(
                    'name' => $sheetName,
                    'data' => $rows,
                    'styles' => $cellStyles
                );
            }
        }
        
        $zip->close();
        
        if (empty($allSheets)) {
            return false;
        }
        
        return $allSheets;
        
    } catch (Exception $e) {
        return false;
    }
}

function column_to_number($col) {
    $col = strtoupper($col);
    $len = strlen($col);
    $num = 0;
    for ($i = 0; $i < $len; $i++) {
        $num = $num * 26 + (ord($col[$i]) - ord('A') + 1);
    }
    return $num - 1;
}

// Try LibreOffice conversion first (pixel-perfect Excel → PDF)
$pdf_content = convert_excel_to_pdf_libreoffice($file_path);

if ($pdf_content !== false) {
    // Output PDF directly - pixel-perfect conversion
    header('Content-Type: application/pdf');
    header('Content-Disposition: inline; filename="' . basename($file_path, '.' . $ext) . '.pdf"');
    header('Content-Length: ' . strlen($pdf_content));
    header('Cache-Control: private, max-age=3600');
    echo $pdf_content;
    exit;
}

// Fallback: Get Excel data for client-side conversion
$excel_data = convert_excel_to_pdf($file_path);

if ($excel_data === false) {
    header('Content-Type: application/json');
    http_response_code(500);
    die(json_encode(array('success' => false, 'error' => 'Failed to convert Excel file')));
}

// Output as JSON for JavaScript to convert to PDF
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Credentials: true');
echo json_encode(array(
    'success' => true,
    'data' => $excel_data
));

