import os
import re
import sys
import tarfile
import binascii


CERT_DATA_TEMPLATE_STRING = "<certificate_data_{0}>"
CERT_LEN_TEMPLATE_STRING = "<certificate_len_{0}>"


def generate_template(tar):
	"""
	Function generates and returns a string that holds the template for the header
	file with specific patterns to be replaced by Certificate binary representation
	and Certificate size in bytes according to the number of certificates in a tar 
	archive
	"""
	cert_number = len(tar.getmembers())
	template_str = "#ifndef CERTS_H\n#define CERTS_H\n\n"
	template_str += "#define NUMBER_OF_CERTS\t\t{}\n\n".format(cert_number)
	
	template_str += "const char cert_binary_storage[NUMBER_OF_CERTS][] = {\n"
	for cert_iter_id in xrange(cert_number):
		template_str += "\t" + CERT_DATA_TEMPLATE_STRING.format(cert_iter_id) + ",\n"
	template_str += "};\n\n"
	
	template_str += "const int cert_size_bytes[NUMBER_OF_CERTS][] = {\n"
	for cert_iter_id in xrange(cert_number):
		template_str += "\t" + CERT_LEN_TEMPLATE_STRING.format(cert_iter_id) + ",\n"
	template_str += "};\n\n"
	
	template_str += "#endif\n\n"
	
	return template_str


def get_c_format_string_from_tar(tar_content_files):
	"""
	Generator function that reads an extracted certificate in binary format, 
	converts it to C format and yields it as a list of hexadecimals
	"""
	
	index = 0
	for tarinfo in tar_content_files:
		certfile = open(tarinfo.name, 'rb')
		binary_content = certfile.read()

		hex_content = binascii.b2a_hex(binary_content)
		hex_content = re.findall('..', hex_content)

		c_format_hex_list = ['0x'+num for num in hex_content]
		c_format_str = "{" + ",".join(c_format_hex_list) + "}"

		yield (index, c_format_str, len(c_format_hex_list))
		index = index + 1
		
		
def replace_data_in_template(template, data_repl_string, size_repl_string, idx):
	"""
	Function takes as parameters the template string, hexadecimal certificate data
	representation string, certificate size in bytes string and certificate number
	and replaces the patterns from template with the given strings according to
	certificate number
	"""
	data_pattern = CERT_DATA_TEMPLATE_STRING.format(idx)
	template = re.sub(data_pattern, data_repl_string, template)

	size_pattern = CERT_LEN_TEMPLATE_STRING.format(idx)
	template = re.sub(size_pattern, size_repl_string, template)
	
	return template

def print_program_info():
	print 	"Usage: python gen_cert_header.py [TAR ARCHIVE] [OPTIONS]  \n\n"			\
			" Program generates C style header file containing array with \n"			\
			"binary representation of certificates in given TAR archive and \n"			\
			"their respective length \n\n"												\
			"Mandatory:\n"																\
			"	-t, --tar [FILE]	Name of the archive holding the certificates\n\n"	\
			"Optional: \n"																\
			"	-c, --cleanup		Removes extracted certificates from archive\n"		\
			"	-h, --help		Outputs usage information and exits\n"		\
			"\n"
	exit(0)


def eval_program_params(argv, argc):
	allowed_params = ["-t","--tar","-h","--help","-c","--cleanup"]

	# Cases where usage information is printed
	if  argc == 1 			or \
		"-h" in argv 		or \
		"--help" in argv 	or \
		("-t" not in argv and "--tar" not in argv) or \
		("-t" in argv and "--tar" in argv):
		print_program_info()

	# Check for wrong parameters
	for param in argv:
		if re.match("^-", param) and param not in allowed_params:
			print_program_info()

	# We are sure that we have either "-t" or "--tar" option so just take the index
	tar_param_idx = 0
	try:
		tar_file_idx = argv.index("--tar")
		tar_file_idx = argv.index("-t")
	except:
		pass

	# Obtain filename of Tar file
	try:
		tar_file = argv[tar_param_idx + 1]
	except IndexError:
		print "Tar file name not specified!\n"
		exit(1)

	if not os.path.exists(tar_file):
		print "File '{}' not found or wrong filename!\n".format(tar_file)
		exit(1)

	do_cleanup = "-c" in argv or "--cleanup" in argv

	return tar_file, do_cleanup
	

if __name__ == "__main__":
	# Check provided parameters for correctness and extract needed data
	tar_file_name, do_cleanup = eval_program_params(sys.argv[1:], len(sys.argv))
	
	# Open tar file as we are sure its name is provided and file exists
	tar = tarfile.open(tar_file_name, "r")
	
	# Generate template string according to tar file contents
	template_string = generate_template(tar)
	
	# Extract all files from tar for further processing
	tar.extractall()

	# Get TarInfo for each file in tar archive
	tar_content_files = tar.getmembers()
	# Process each certificate file and put its data in template
	for idx, cert_data_c_format, cert_size_bytes in get_c_format_string_from_tar(tar_content_files):
		template_string = replace_data_in_template(	template_string, 
													cert_data_c_format, 
													str(cert_size_bytes), 
													idx)
	# Close tar file as it's not needed anymore
	tar.close()		
	
	# Create(truncate) the header file where data is stored
	c_header = open("certs.h", "w")
	c_header.write(template_string)
	c_header.close()

	# If cleanup is required remove all extracted files
	if do_cleanup:
		for tarinfo in tar_content_files:
			os.remove(tarinfo.name)
	
	
	