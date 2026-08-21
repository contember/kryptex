import {
  expectArray,
  expectBoolean,
  expectCanonicalBase64UrlLength,
  expectExactObject,
  expectString,
  expectUtf8Length,
  readProperty
} from "./validation.js";

export interface SendTextPayload {
  readonly kind: "text";
  readonly text: string;
}

export interface SendField {
  readonly label: string;
  readonly type: ValueFieldType;
  readonly value: string;
}

export interface SendFieldsPayload {
  readonly fields: readonly SendField[];
  readonly kind: "fields";
}

export type SendPayload = SendTextPayload | SendFieldsPayload;

/**
 * One vocabulary for every labelled value, on both the send and the request side.
 * `long-*` means a multi-line value; `*-secret` means sensitive, so clients mask
 * entry where the control allows it and render the value in monospace.
 */
export type ValueFieldType = "secret" | "text" | "long-secret" | "long-text";
export type RequestFieldType = ValueFieldType | "instruction";

export interface RequestSchemaField {
  readonly help: string;
  readonly id: string;
  readonly label: string;
  readonly required: boolean;
  readonly type: RequestFieldType;
}

export interface RequestSchemaPayload {
  readonly fields: readonly RequestSchemaField[];
  readonly kind: "request-schema";
  readonly recipientPublicKey: string;
  readonly title: string;
}

export interface RequestAnswer {
  readonly id: string;
  readonly value: string;
}

export interface RequestResponsePayload {
  readonly answers: readonly RequestAnswer[];
  readonly kind: "request-response";
  readonly schema: RequestSchemaPayload;
}

export type CanonicalPayload = SendPayload | RequestSchemaPayload | RequestResponsePayload;

function parseValueFieldType(value: unknown, context: string): ValueFieldType {
  if (value === "secret" || value === "text" || value === "long-secret" || value === "long-text") {
    return value;
  }
  throw new TypeError(`${context} has an unsupported field type`);
}

function parseSendField(value: unknown, index: number): SendField {
  const context = `send.fields[${index}]`;
  const object = expectExactObject(value, ["label", "type", "value"], context);
  return {
    label: expectUtf8Length(readProperty(object, "label", context), 1, 120, `${context}.label`),
    type: parseValueFieldType(readProperty(object, "type", context), `${context}.type`),
    value: expectUtf8Length(readProperty(object, "value", context), 1, 262144, `${context}.value`)
  };
}

export function parseSendPayload(value: unknown): SendPayload {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("send payload must be an object");
  }
  const kind = readProperty(value, "kind", "send");
  if (kind === "text") {
    const object = expectExactObject(value, ["kind", "text"], "send text");
    return {
      kind: "text",
      text: expectUtf8Length(readProperty(object, "text", "send text"), 1, 262144, "send text.text")
    };
  }
  if (kind === "fields") {
    const object = expectExactObject(value, ["fields", "kind"], "send fields");
    const fields = expectArray(readProperty(object, "fields", "send fields"), 1, 32, "send fields.fields");
    return {
      fields: fields.map(parseSendField),
      kind: "fields"
    };
  }
  throw new TypeError("send payload has an unsupported kind");
}

function parseRequestFieldType(value: unknown, context: string): RequestFieldType {
  if (value === "instruction") {
    return value;
  }
  return parseValueFieldType(value, context);
}

function parseRequestSchemaField(value: unknown, index: number): RequestSchemaField {
  const context = `request schema.fields[${index}]`;
  const object = expectExactObject(value, ["help", "id", "label", "required", "type"], context);
  const id = expectString(readProperty(object, "id", context), `${context}.id`);
  if (!/^[a-z0-9]{8,32}$/.test(id)) {
    throw new TypeError(`${context}.id is invalid`);
  }
  const required = expectBoolean(readProperty(object, "required", context), `${context}.required`);
  const type = parseRequestFieldType(readProperty(object, "type", context), `${context}.type`);
  if (type === "instruction" && required) {
    throw new TypeError(`${context} instructions cannot be required`);
  }
  return {
    help: expectUtf8Length(readProperty(object, "help", context), 0, 500, `${context}.help`),
    id,
    label: expectUtf8Length(readProperty(object, "label", context), 1, 120, `${context}.label`),
    required,
    type
  };
}

export function parseRequestSchemaPayload(value: unknown): RequestSchemaPayload {
  const object = expectExactObject(
    value,
    ["fields", "kind", "recipientPublicKey", "title"],
    "request schema"
  );
  if (readProperty(object, "kind", "request schema") !== "request-schema") {
    throw new TypeError("request schema.kind is invalid");
  }
  const fieldValues = expectArray(readProperty(object, "fields", "request schema"), 1, 32, "request schema.fields");
  const fields = fieldValues.map(parseRequestSchemaField);
  const identifiers = new Set(fields.map((field) => field.id));
  if (identifiers.size !== fields.length) {
    throw new TypeError("request schema field IDs must be unique");
  }
  return {
    fields,
    kind: "request-schema",
    recipientPublicKey: expectCanonicalBase64UrlLength(
      readProperty(object, "recipientPublicKey", "request schema"),
      32,
      "request schema.recipientPublicKey"
    ),
    title: expectUtf8Length(readProperty(object, "title", "request schema"), 1, 120, "request schema.title")
  };
}

function schemasEqual(left: RequestSchemaPayload, right: RequestSchemaPayload): boolean {
  if (
    left.recipientPublicKey !== right.recipientPublicKey ||
    left.title !== right.title ||
    left.fields.length !== right.fields.length
  ) {
    return false;
  }
  return left.fields.every((field, index) => {
    const other = right.fields[index];
    return (
      field.help === other?.help &&
      field.id === other.id &&
      field.label === other.label &&
      field.required === other.required &&
      field.type === other.type
    );
  });
}

export function parseRequestResponsePayload(
  value: unknown,
  trustedSchema?: RequestSchemaPayload
): RequestResponsePayload {
  const object = expectExactObject(value, ["answers", "kind", "schema"], "request response");
  if (readProperty(object, "kind", "request response") !== "request-response") {
    throw new TypeError("request response.kind is invalid");
  }
  const schema = parseRequestSchemaPayload(readProperty(object, "schema", "request response"));
  if (trustedSchema !== undefined && !schemasEqual(schema, trustedSchema)) {
    throw new TypeError("request response schema does not match the trusted schema");
  }
  const expectedFields = schema.fields.filter((field) => field.type !== "instruction");
  const answerValues = expectArray(
    readProperty(object, "answers", "request response"),
    expectedFields.length,
    expectedFields.length,
    "request response.answers"
  );
  const answers = answerValues.map((answerValue, index): RequestAnswer => {
    const context = `request response.answers[${index}]`;
    const answerObject = expectExactObject(answerValue, ["id", "value"], context);
    const expectedField = expectedFields[index];
    if (expectedField === undefined) {
      throw new TypeError(`${context} has no corresponding schema field`);
    }
    const id = expectString(readProperty(answerObject, "id", context), `${context}.id`);
    if (id !== expectedField.id) {
      throw new TypeError(`${context}.id is not in schema order`);
    }
    const answer = expectUtf8Length(readProperty(answerObject, "value", context), 0, 262144, `${context}.value`);
    if (expectedField.required && answer.length === 0) {
      throw new TypeError(`${context}.value is required`);
    }
    return { id, value: answer };
  });
  return { answers, kind: "request-response", schema };
}

export function serializeCanonicalPayload(payload: CanonicalPayload): string {
  if (payload.kind === "text") {
    return JSON.stringify({ kind: payload.kind, text: payload.text });
  }
  if (payload.kind === "fields") {
    return JSON.stringify({
      fields: payload.fields.map((field) => ({
        label: field.label,
        type: field.type,
        value: field.value
      })),
      kind: payload.kind
    });
  }
  if (payload.kind === "request-schema") {
    return JSON.stringify({
      fields: payload.fields.map((field) => ({
        help: field.help,
        id: field.id,
        label: field.label,
        required: field.required,
        type: field.type
      })),
      kind: payload.kind,
      recipientPublicKey: payload.recipientPublicKey,
      title: payload.title
    });
  }
  return JSON.stringify({
    answers: payload.answers.map((answer) => ({ id: answer.id, value: answer.value })),
    kind: payload.kind,
    schema: {
      fields: payload.schema.fields.map((field) => ({
        help: field.help,
        id: field.id,
        label: field.label,
        required: field.required,
        type: field.type
      })),
      kind: payload.schema.kind,
      recipientPublicKey: payload.schema.recipientPublicKey,
      title: payload.schema.title
    }
  });
}
