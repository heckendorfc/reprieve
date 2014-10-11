/* Copyright 2014, Heckendorf */

#include "io_setup.h"

int io_general_init(yamldom_data_t *ydd){
	memset(&ydd->parser,0,sizeof(ydd->event));
	memset(&ydd->emitter,0,sizeof(ydd->emitter));

	if(!yaml_emitter_initialize(&ydd->emitter))
		goto error;

	if(ydd->infd){
		if(!yaml_parser_initialize(&ydd->parser))
			goto error;

		yaml_parser_set_input_file(&ydd->parser, ydd->infd);
		yaml_parser_set_encoding(&ydd->parser,YAML_UTF8_ENCODING);
	}

	yaml_emitter_set_output_file(&ydd->emitter, ydd->outfd);
	yaml_emitter_set_canonical(&ydd->emitter,0);
	yaml_emitter_set_unicode(&ydd->emitter,0);

	return 0;

error:
	return 1;
}

int io_general_close(yamldom_data_t *ydd){
	if(ydd->infd)
		yaml_parser_delete(&ydd->parser);

	yaml_emitter_delete(&ydd->emitter);

	return 0;
}
