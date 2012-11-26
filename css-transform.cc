/** @file

  A brief file description

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */
/*
 * css-transform.c:  (Derived from append-transform)
 *    Usage:
 *     (NT): CssTransform.dll <filename>
 *     (Solaris): css-transform.so <filename>
 */

#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <ts/ts.h>
#include <pcre.h>
#include <pcrecpp.h>

#define STATE_BUFFER_DATA     0
#define STATE_TRANSFORM_DATA  1 
#define STATE_OUTPUT_DATA     2

#define ASSERT_SUCCESS(_x) TSAssert ((_x) == TS_SUCCESS)

using namespace std;

typedef struct {
  int state;
  TSVIO output_vio;
  TSIOBuffer output_buffer;
  TSIOBufferReader output_reader;
  TSIOBuffer min_buffer;
  TSIOBufferReader min_buffer_reader;
} Data;

static Data * my_data_alloc() {
  Data *data;
  data = (Data *) TSmalloc(sizeof(Data));
  TSReleaseAssert(data);

  data->state = STATE_BUFFER_DATA;

  data->output_vio = NULL;
  data->output_buffer = NULL;
  data->output_reader = NULL;
  data->min_buffer = TSIOBufferCreate();
  data->min_buffer_reader = TSIOBufferReaderAlloc(data->min_buffer);
  TSAssert(data->min_buffer_reader);
  return data;
}

static void my_data_destroy(Data * data) {
  if (data) {
    if (data->output_buffer) {
      TSIOBufferDestroy(data->output_buffer);
    }
    if (data->min_buffer) {
      TSIOBufferDestroy(data->min_buffer);
    }

    TSfree(data);
  }
}

static void write_iobuffer(const char *buf, int len, TSIOBuffer output) {
  TSIOBufferBlock block;
  char *ptr_block;
  int64_t ndone, ntodo, towrite, avail;

  ndone = 0;
  ntodo = len;
  while (ntodo > 0) {
    block = TSIOBufferStart(output);
    ptr_block = TSIOBufferBlockWriteStart(block, &avail);
    towrite = min(ntodo, avail);
    memcpy(ptr_block, buf + ndone, towrite);
    TSIOBufferProduce(output, towrite);
    ntodo -= towrite;
    ndone += towrite;
  }
}
static void cssmin_transform(Data *data) {
  TSIOBufferBlock block = TSIOBufferReaderStart(data->output_reader);

  while (block != NULL) {
    int64_t blocklen;
    const char * blockptr = TSIOBufferBlockReadStart(block, data->output_reader, &blocklen);
    string str (blockptr);

    // Strip extra spaces
    pcrecpp::RE("\\s+").GlobalReplace(" ", &str);
    pcrecpp::RE("\\s}\\s*").GlobalReplace("}", &str);
    pcrecpp::RE("\\s{\\s*").GlobalReplace("{", &str);

    //  Remove extra semicolons
    pcrecpp::RE(";+").GlobalReplace(";", &str);
    pcrecpp::RE(":(?:0 )+0;").GlobalReplace(":0;", &str);

    // write this block and move on
    write_iobuffer(str.c_str(), strlen(str.c_str()), data->min_buffer);

    // Parse next block
    block = TSIOBufferBlockNext(block);
  }
}

static int handle_buffering(TSCont contp, Data * data) {
  TSVIO write_vio;
  int towrite;
  int avail;

  /* Get the write VIO for the write operation that was performed on
     ourself. This VIO contains the buffer that we are to read from
     as well as the continuation we are to call when the buffer is
     empty. */
  write_vio = TSVConnWriteVIOGet(contp);

  /* Create the output buffer and its associated reader */
  if (!data->output_buffer) {
    data->output_buffer = TSIOBufferCreate();
    TSAssert(data->output_buffer);
    data->output_reader = TSIOBufferReaderAlloc(data->output_buffer);
    TSAssert(data->output_reader);
  }

  /* We also check to see if the write VIO's buffer is non-NULL. A
     NULL buffer indicates that the write operation has been
     shutdown and that the continuation does not want us to send any
     more WRITE_READY or WRITE_COMPLETE events. For this buffered
     transformation that means we're done buffering data. */

  if (!TSVIOBufferGet(write_vio)) {
    data->state = STATE_TRANSFORM_DATA;
    return 0;
  }

  towrite = TSVIONTodoGet(write_vio);
  if (towrite > 0) {
    /* The amount of data left to read needs to be truncated by
       the amount of data actually in the read buffer. */

    avail = TSIOBufferReaderAvail(TSVIOReaderGet(write_vio));
    if (towrite > avail) {
      towrite = avail;
    }

    if (towrite > 0) {
      /* Copy the data from the read buffer to the input buffer. */
      TSIOBufferCopy(data->output_buffer, TSVIOReaderGet(write_vio), towrite, 0);

      /* Tell the read buffer that we have read the data and are no
         longer interested in it. */
      TSIOBufferReaderConsume(TSVIOReaderGet(write_vio), towrite);

      /* Modify the write VIO to reflect how much data we've
         completed. */
      TSVIONDoneSet(write_vio, TSVIONDoneGet(write_vio)
		    + towrite);
    }
  }

  /* Now we check the write VIO to see if there is data left to read. */
  if (TSVIONTodoGet(write_vio) > 0) {
    if (towrite > 0) {
      /* Call back the write VIO continuation to let it know that we
         are ready for more data. */
      TSContCall(TSVIOContGet(write_vio), TS_EVENT_VCONN_WRITE_READY, write_vio);
    }
  } else {
    data->state = STATE_TRANSFORM_DATA;
    TSContCall(TSVIOContGet(write_vio), TS_EVENT_VCONN_WRITE_COMPLETE, write_vio);
  }

  return 1;
}

static int handle_output(TSCont contp, Data * data) {
  /* Check to see if we need to initiate the output operation. */
  if (!data->output_vio) {
    TSVConn output_conn;

    /* Get the output connection where we'll write data to. */
    output_conn = TSTransformOutputVConnGet(contp);

    data->output_vio =
      TSVConnWrite(output_conn, contp, data->min_buffer_reader, TSIOBufferReaderAvail(data->min_buffer_reader));

    TSAssert(data->output_vio);
  }
  return 1;
}

static void handle_transform(TSCont contp) {
  Data *data;
  int done;

  /* Get our data structure for this operation. The private data
     structure contains the output VIO and output buffer. If the
     private data structure pointer is NULL, then we'll create it
     and initialize its internals. */

  data = (Data *) TSContDataGet(contp);
  if (!data) {
    data = my_data_alloc();
    TSContDataSet(contp, data);
  }

  do {
    switch (data->state) {
    case STATE_BUFFER_DATA:
      done = handle_buffering(contp, data);
      break;
    case STATE_TRANSFORM_DATA:
      cssmin_transform(data);
    case STATE_OUTPUT_DATA:
      done = handle_output(contp, data);
      break;
    default:
      done = 1;
      break;
    }
  } while (!done);
}


static int transform(TSCont contp, TSEvent event, void *edata) {
  //Check to see if the transformation has been closed by a call to TSVConnClose
  if (TSVConnClosedGet(contp)) {
    my_data_destroy((Data *) TSContDataGet(contp));
    TSContDestroy(contp);
  } else {
    switch (event) {
    case TS_EVENT_ERROR: {
        TSVIO write_vio;
        write_vio = TSVConnWriteVIOGet(contp);
        TSContCall(TSVIOContGet(write_vio), TS_EVENT_ERROR, write_vio);
      }
      break;
    case TS_EVENT_VCONN_WRITE_COMPLETE:
      TSVConnShutdown(TSTransformOutputVConnGet(contp), 0, 1);
      break;
    case TS_EVENT_VCONN_WRITE_READY:
    default:
      handle_transform(contp);
      break;
    }
  }
  return 0;
}

static int transformable(TSHttpTxn txnp) {
  TSMBuffer bufp;
  TSMLoc hdr_loc;
  TSMLoc field_loc;
  TSHttpStatus resp_status;
  const char *value;
  int val_length;

  TSHttpTxnServerRespGet(txnp, &bufp, &hdr_loc);

  if (TS_HTTP_STATUS_OK == (resp_status = TSHttpHdrStatusGet(bufp, hdr_loc))) {
    field_loc = TSMimeHdrFieldFind(bufp, hdr_loc, "Content-Type", 12);
    if (!field_loc) {
      ASSERT_SUCCESS(TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc));
      return 0;
    }


    value = TSMimeHdrFieldValueStringGet(bufp, hdr_loc, field_loc, 0, &val_length);
#ifndef _WIN32
    if (value && (strncasecmp(value, "text/css", sizeof("text/css") - 1) == 0)) {
#else
    if (value && (strnicmp(value, "text/css", sizeof("text/css") - 1) == 0)) {
#endif
      ASSERT_SUCCESS(TSHandleMLocRelease(bufp, hdr_loc, field_loc));
      ASSERT_SUCCESS(TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc));
      return 1;
    } else {
      ASSERT_SUCCESS(TSHandleMLocRelease(bufp, hdr_loc, field_loc));
      ASSERT_SUCCESS(TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc));
      return 0;
    }
  }
  return 0;
}

static void transform_add(TSHttpTxn txnp) {
  TSVConn connp;
  connp = TSTransformCreate(transform, txnp);
  TSHttpTxnHookAdd(txnp, TS_HTTP_RESPONSE_TRANSFORM_HOOK, connp);
}

static int transform_plugin(TSCont contp, TSEvent event, void *edata) {
  TSHttpTxn txnp = (TSHttpTxn) edata;
  switch (event) {
  case TS_EVENT_HTTP_READ_RESPONSE_HDR:
    if (transformable(txnp)) {
      transform_add(txnp);
    }
    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
    return 0;
  default:
    break;
  }

  return 0;
}

int check_ts_version () {
  const char *ts_version = TSTrafficServerVersionGet();
  int result = 0;

  if (ts_version) {
    int major_ts_version = 0;
    int minor_ts_version = 0;
    int patch_ts_version = 0;
    if (sscanf(ts_version, "%d.%d.%d", &major_ts_version, &minor_ts_version, &patch_ts_version) != 3) {
        return 0;
    }
    /* Need at least TS 2.0 */
    if (major_ts_version >= 2) {
       result = 1;
    }
  }
  return result;
}

void TSPluginInit(int argc, const char *argv[]) {
    TSPluginRegistrationInfo info;
    info.plugin_name = (char *)"css-transform";
    info.vendor_name = (char *)"css transform";
    info.support_email = (char *)"css@domain.tld";
    if (TSPluginRegister(TS_SDK_VERSION_3_0, &info) != TS_SUCCESS) {
      TSError("Plugin registration failed.\n");
      goto Lerror;
    }
    if (!check_ts_version()) {
      TSError("Plugin requires Traffic Server 3.0 or later\n");
      goto Lerror;
    }
    TSHttpHookAdd(TS_HTTP_READ_RESPONSE_HDR_HOOK, TSContCreate(transform_plugin, NULL));
    return;
Lerror:
    TSError("[css-transform] Unable to initialize plugin\n");
}
