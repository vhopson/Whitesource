## Import Whitesource Results
# This is a Q&D importer of results from Whitesource.  Takes in an XML file,
# and reformats it to Code Dx results.
# Currently, all of the results use CWE 937 as that is a catch all for
# vulnerable libraries.

import argparse
import xml.etree.ElementTree as ET
import time
from datetime import date

## Main Subroutine
#
def main(args) :
	input_file = args.in_file
	output_file = args.out_file

	# Set up for, and begin the processing of the input XML file
	
	print("Processing", input_file, "into", output_file)
	in_tree = ET.parse(input_file)
	in_root = in_tree.getroot()
	
	# Begin the XML creation for the output file
	
	today = date.today()
	report_element = ET.Element('report')
	report_element.set('date', str(today))
	findings_element = ET.SubElement(report_element, 'findings')

	# insert elements to satisfy our output XML
	for vulnerability in in_root.findall('vulnerability') :
		severity = vulnerability.find('severity')
		library = vulnerability.find('library')
		name = vulnerability.find('name')
		score = vulnerability.find('score')
		published = vulnerability.find('published')
		description = vulnerability.find('description')
		
		# create the subelement that contains the finding
		finding_element = ET.SubElement(findings_element, 'finding')
		finding_element.set('severity', severity.text)
		finding_element.set('generator', 'Whitesource');
		
		# add a CWE element
		cwe = ET.SubElement(finding_element, 'cwe')
		cwe.set('id', '937')
		
		# Add a tool element
		tool = ET.SubElement(finding_element, 'tool')
		tool.set('name', 'Whitesource')
		tool.set('category', 'Insecure Library')
		tool.set('code', '')
		
		# Add location if that is necessary
		location_element = ET.SubElement(finding_element, 'location')
		location_element.set('type', 'file')
		location_element.set('path', library.text)
		
		# Add description
		desc_element = ET.SubElement(finding_element, 'description')
		desc_element.set('format', 'plain-text')
		desc_element.text = description.text
		
	tree = ET.ElementTree(report_element)
	tree.write(output_file, xml_declaration=True, encoding='utf-8', method='xml')


## Main Entry Point
#
parser = argparse.ArgumentParser()
parser.add_argument("--in_file",  "-i", required=True, help="Select input XML file.")
parser.add_argument("--out_file", "-o", required=True, help="Select output XML file.")
args = parser.parse_args()

if __name__ == "__main__" :
	main(args)
